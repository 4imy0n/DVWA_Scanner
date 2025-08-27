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
        '<script>alert("XSS1")</script>',
        '<img src=x onerror=alert("XSS2")>',
        '<svg/onload=alert("XSS3")>',
        "';alert('XSS4');//",
        '\"><script>alert(\"XSS5\")</script>'
    ]

    cookie_items = []
    for chunk in headers.get("Cookie", "").split(";"):
        if "=" in chunk:
            k, v = chunk.strip().split("=", 1)
            cookie_items.append((k, v))

    ff_opt = FirefoxOptions()
    ff_opt.binary_location = "/snap/firefox/current/usr/lib/firefox/firefox"
    ff_opt.add_argument("--headless")
    ff_opt.add_argument("--disable-gpu")
    ff_opt.add_argument("--no-sandbox")
    ff_opt.set_preference("dom.disable_open_during_load", False)

    gecko_path = shutil.which("geckodriver") or "/snap/bin/geckodriver"
    service = FirefoxService(executable_path=gecko_path)

    console.print("[*] Firefox-headless Reflected-XSS 스캔 시작\n", style="cyan")

    final_result = []
    printed_table_title = False

    for d in find_path_dic:
        if d.get("method", "GET").upper() != "GET":
            continue
        if "/vulnerabilities/xss_r/" not in d.get("url", ""):
            continue

        base_url = d["url"].rstrip("/")
        param_list = d.get("param", [])

        driver = webdriver.Firefox(service=service, options=ff_opt)
        driver.set_page_load_timeout(15)

        driver.get(base_url)
        driver.delete_all_cookies()
        for k, v in cookie_items:
            driver.add_cookie({"name": k, "value": v})

        for p_name in param_list:
            for payload in xss_payloads:
                test_url = f"{base_url}?{urlencode({p_name: payload})}"
                try:
                    driver.get(test_url)
                except Exception:
                    continue

                try:
                    WebDriverWait(driver, 3).until(EC.alert_is_present())
                    alert = driver.switch_to.alert
                    alert_text = alert.text
                    alert.accept()

                    if not printed_table_title:
                        aligned_title = Align("[italic bold white]Reflected XSS 탐지 결과[/]", align="center")
                        console.print(aligned_title)
                        printed_table_title = True

                    table = Table(show_lines=True, title=None)
                    table.add_column("항목", style="white", justify="center")
                    table.add_column("내용", style="white", justify="center")
                    table.add_row("URL", test_url)
                    table.add_row("VULN NAME", "Reflected XSS")
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
                            aligned_title = Align("[italic bold green]Reflected XSS 탐지 결과[/]", align="center")
                            console.print(aligned_title)
                            printed_table_title = True

                        table = Table(show_lines=True, title=None)
                        table.add_column("항목", style="white", justify="center")
                        table.add_column("내용", style="white", justify="center")
                        table.add_row("URL", test_url)
                        table.add_row("VULN NAME", "Reflected XSS")
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
        console.print("[!] Reflected XSS 취약점이 없습니다.", style="bold red")
        return "[!] Reflected XSS 취약점이 없습니다."

    console.print(f"[✓] Reflected XSS 총 {len(final_result)}건 탐지 완료.", style="bold green")
    return final_result
