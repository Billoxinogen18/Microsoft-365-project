import os, time
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager

templates_dir = os.path.join(os.path.dirname(__file__), 'templates')
os.makedirs(templates_dir, exist_ok=True)

options = Options()
options.binary_location = '/usr/bin/chromium'
options.add_argument('--headless')
options.add_argument('--no-sandbox')
options.add_argument('--disable-dev-shm-usage')

service = Service(ChromeDriverManager().install())
driver = webdriver.Chrome(service=service, options=options)

def save(name):
    path = os.path.join(templates_dir, f'{name}.html')
    with open(path, 'w', encoding='utf-8') as fh:
        fh.write(driver.page_source)

try:
    driver.get('https://login.microsoftonline.com/')
    time.sleep(3)
    save('login')

    # email next
    driver.find_element(By.NAME, 'loginfmt').send_keys('test@example.com')
    driver.find_element(By.ID, 'idSIButton9').click()
    time.sleep(3)
    save('password')

    # enter dummy password to attempt 2fa page
    try:
        driver.find_element(By.NAME, 'passwd').send_keys('dummyPass123!')
        driver.find_element(By.ID, 'idSIButton9').click()
        time.sleep(5)
        save('twofactor')
    except Exception:
        pass
finally:
    driver.quit()

print('Templates saved to', templates_dir) 