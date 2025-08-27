from bs4 import BeautifulSoup
import requests
from pyfiglet import figlet_format
from termcolor import colored
from tabulate import tabulate
from rich.progress import Progress
from modules import brute
from modules import csrf
from modules import exec_module
import modules.file_include as file_include

# from modules import crawler
import os

check_key = ['url', 'method', 'param']
find_path_list = []
find_path_dic = []
save_craw = ""
save_brute = ""
save_exec = ""
save_csrf = ""
save_file_include = ""
save_brute2 = ""
save_exec2 = ""
save_csrf2 = ""
save_file_include2 = ""

def print_crawling_banner():
    banner = figlet_format("Crawling", font="slant")
    print(colored(banner, "green", attrs=["bold"]))
    print(colored("[*] 예) http://192.168.65.2/DVWA/ -c [세션ID] -l [low|medium|high] -k", "white"))

def findPathForm(url_k, soup, headers):
    try:
        for location in soup.select('form'):
            action = location['action']
            if 'http' not in action:
                action = f'{url_k}{action}'
            if action not in find_path_list:
                url = deny_url_check(action)
                if url:
                    find_path_list.append(url)
    except Exception as e:
        print(f"findPathForm_ERROR : {e}")

def findPathA(url_k, soup, headers):
    try:
        for location in soup.select('a'):
            href = location['href']
            if 'http' not in href:
                href = f'{url_k}{href}'
            if href not in find_path_list:
                url = deny_url_check(href)
                if not url:
                    continue
                if "high" in headers['Cookie']:
                    if url == "http://192.168.65.2/DVWA/vulnerabilities/sqli/":
                        url += "session-input.php"
                    elif url == "http://192.168.65.2/DVWA/vulnerabilities/sqli_blind/":
                        url += "cookie-input.php"
                find_path_list.append(url)
    except Exception as e:
        print(f"findPathA_ERROR : {e}")

def findPathInput(url_k, soup, headers):
    try:
        for location in soup.select('input'):
            if 'onclick' in location.attrs:
                onclick = location['onclick']
                for delim in ("'", '"'):
                    if delim in onclick:
                        parts = onclick.split(delim)
                        if len(parts) > 1:
                            path = parts[1]
                            url = f'{url_k}{path}' if 'http' not in path else path
                            if url not in find_path_list:
                                url = deny_url_check(url)
                                if url:
                                    find_path_list.append(url)
                        break
    except Exception as e:
        print(f"findPathInput_ERROR : {e}")

def deny_url_check(url):
    deny_url_list = [
        'http://192.168.65.2/DVWA/logout.php', 
        'http://192.168.65.2/DVWA/instructions.php', 
        'http://192.168.65.2/DVWA/setup.php', 
        'http://192.168.65.2/DVWA/vulnerabilities/captcha/',
        'http://192.168.65.2/DVWA/#',
        'http://192.168.65.2/DVWA/.',
        'http://192.168.65.2/DVWA/security.php',
        'http://192.168.65.2/DVWA/phpinfo.php',
        'http://192.168.65.2/DVWA/about.php',
        'https://www.virtualbox.org/',
        'https://www.vmware.com/',
        'https://www.apachefriends.org/',
        'https://github.com/webpwnized/mutillidae',
        'https://owasp.org/www-project-vulnerable-web-applications-directory',
        'http://192.168.65.2/DVWA/vulnerabilities/api/',
        'http://192.168.65.2/DVWA/vulnerabilities/cryptography/',
        'http://192.168.65.2/DVWA/vulnerabilities/authbypass/',
        'http://192.168.65.2/DVWA/vulnerabilities/open_redirect/',
        'http://192.168.65.2/DVWA/vulnerabilities/weak_id/',
        'http://192.168.65.2/DVWA/vulnerabilities/csp/',
        'http://192.168.65.2/DVWA/vulnerabilities/javascript/'
    ]
    return url if url not in deny_url_list else 0

def get_param_check(href):
    param_name = []
    if '?' in href:
        method = 'get'
        a = href.split("?")
        if '&' in a[1]:
            for data in a[1].split("&"):
                param_name.append(data.split('=')[0])
        else:
            param_name.append(a[1].split('=')[0])
        return method, param_name
    return '?', '?'

def findParam(url_k, soup, headers):
    for location in soup.select('form'):
        tmp_dic = {}
        param_list = []
        if 'method' in location.attrs:
            method = location['method']
            tmp_dic['url'] = url_k
            tmp_dic['method'] = method
            for tag in soup.select('input, textarea, select'):
                if 'name' in tag.attrs:
                    param_list.append(tag['name'])
            tmp_dic['param'] = param_list
            if all(key in tmp_dic for key in check_key) and tmp_dic not in find_path_dic and tmp_dic['param'] and tmp_dic['method'] != '?':
                find_path_dic.append(tmp_dic)

    for location in soup.select('a'):
        method, param = get_param_check(url_k)
        tmp_dic = {'url': url_k, 'method': method, 'param': param}
        if all(key in tmp_dic for key in check_key) and tmp_dic not in find_path_dic and param and method != '?':
            find_path_dic.append(tmp_dic)

def main_crawl_only(url_k, cookie, level):
    find_path_list.clear()
    find_path_dic.clear()
    headers = {'Cookie': f'{cookie}; {level}'}
    try:
        res = requests.get(url_k, headers=headers)
        soup = BeautifulSoup(res.text, "html.parser")
        findPathForm(url_k, soup, headers)
        findPathA(url_k, soup, headers)
        findPathInput(url_k, soup, headers)
        with Progress() as progress:
            task = progress.add_task("[cyan]크롤링 진행 중...", total=len(find_path_list))
            for url in find_path_list:
                try:
                    res = requests.get(url, headers=headers)
                    soup = BeautifulSoup(res.text, "html.parser")
                    findParam(url, soup, headers)
                except Exception as e:
                    print(f"[!] 요청 실패: {url} - {e}")
                progress.update(task, advance=1)
        return soup, headers, find_path_dic
    except Exception as e:
        print(colored(f"[!] 크롤링 실패: {e}", "red"))
        return None, headers, []

def run():          
    main()

def main():
    print_crawling_banner()
    url_k = ''
    cookie = 'PHPSESSID='
    level = 'security='
    headers = {}
    while True:
        command = input("\n> ").strip()
        if not command:
            continue
        command_s = command.split(" ")
        if 'http' not in command_s[0]:
            print("\n[!] 명령어가 잘못되어있습니다.")
            continue
        url_k = command_s[0]
        if '-c' in command_s:
            cookie += command_s[command_s.index('-c') + 1] + "; "
        if '-l' in command_s:
            level += command_s[command_s.index('-l') + 1] + ";"
        headers['Cookie'] = cookie + level
        headers['Referer'] = url_k
        global save_craw, save_brute, save_exec, save_csrf, save_file_include
        global save_brute2, save_exec2, save_csrf2, save_file_include2
        if '-k' in command_s:
            res = requests.get(url_k, headers=headers)
            soup = BeautifulSoup(res.text, "html.parser")
            findPathForm(url_k, soup, headers)
            findPathA(url_k, soup, headers)
            findPathInput(url_k, soup, headers)
            print("\n")
            with Progress() as progress:
                task = progress.add_task("[cyan]크롤링 진행 중...", total=len(find_path_list))
                for url in find_path_list:
                    headers['Cookie'] = cookie + level
                    try:
                        res = requests.get(url, headers=headers)
                        soup = BeautifulSoup(res.text, "html.parser")
                        findParam(url, soup, headers)
                    except Exception as e:
                        print(f"[!] 요청 실패: {url} - {e}")
                    progress.update(task, advance=1)
            print("\n")
            print(tabulate(find_path_dic, headers="keys", tablefmt="fancy_grid"))
            save_craw = tabulate(find_path_dic, headers="keys", tablefmt="fancy_grid")
        if '-a' in command_s:
            res = requests.get(url_k, headers=headers)
            soup = BeautifulSoup(res.text, "html.parser")
            findPathForm(url_k, soup, headers)
            findPathA(url_k, soup, headers)
            findPathInput(url_k, soup, headers)
            for url in find_path_list:
                res = requests.get(url, headers=headers)
                soup = BeautifulSoup(res.text, "html.parser")
                findParam(url, soup, headers)
            save_brute = brute.run(soup, headers, find_path_dic)
            save_exec = exec_module.run(soup, headers, find_path_dic)
            save_csrf = csrf.run(soup, headers, find_path_dic)
            save_file_include = file_include.run(soup, headers, find_path_dic)
        if '-v' in command_s:
            vuln_type = command_s[command_s.index('-v') + 1]
            # 크롤링 먼저 수행
            res = requests.get(url_k, headers=headers)
            soup = BeautifulSoup(res.text, "html.parser")
            findPathForm(url_k, soup, headers)
            findPathA(url_k, soup, headers)
            findPathInput(url_k, soup, headers)     
            for url in find_path_list:
                try:
                    res = requests.get(url, headers=headers)
                    soup = BeautifulSoup(res.text, "html.parser")
                    findParam(url, soup, headers)
                except Exception as e:
                    print(f"[!] 요청 실패: {url} - {e}")

            # 크롤링 후 탐지 수행
            if vuln_type == 'brute':
                save_brute2 = brute.run2(soup, headers, find_path_dic)
            elif vuln_type == 'exec':
                save_exec2 = exec.run2(soup, headers, find_path_dic)
            elif vuln_type == 'csrf':
                save_csrf2 = csrf.run2(soup, headers, find_path_dic)
            elif vuln_type == 'file_include':
                save_file_include2 = file_include.run2(soup, headers, find_path_dic)
            else:
                print(colored(f"[!] 알 수 없는 취약점 타입: {vuln_type}", "red"))
        if '-s' in command_s:
            save_n = command_s[command_s.index('-s') + 1].replace('.txt', '')
            if os.path.isfile(save_n):
                print("이미 존재하는 파일입니다.")
                continue
            with open(save_n, "a", encoding="utf-8") as f:
                if '-a' in command_s:
                    f.write(save_brute)
                    f.write(save_exec)
                    f.write(save_csrf)
                    f.write(save_file_include)
                elif '-k' in command_s:
                    f.write(save_craw)
                elif '-v' in command_s:
                    vuln_type = command_s[command_s.index('-v') + 1]
                    if vuln_type == 'brute':
                        f.write(save_brute2)
                    elif vuln_type == 'exec':
                        f.write(save_exec2)
                    elif vuln_type == 'csrf':
                        f.write(save_csrf2)
                    elif vuln_type == 'file_include':
                        f.write(save_file_include2)
            print(f"[✓] 결과가 파일로 저장되었습니다: {save_n}")
        if any(opt in command_s for opt in ['-k', '-a', '-v']):
            break

if __name__ == "__main__":
    run()