from flask import Flask, request, render_template
from flask.wrappers import Response
import requests
'''
import time
import re


from selenium import webdriver

from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.by import By
from selenium.common.exceptions import TimeoutException
'''

application = Flask(__name__)


@application.route('/')
def hello_world():
    return 'Hello World!!!'


@application.route('/health')
def healthy():
    return "health"


@application.route('/api')
def api():
    token = request.cookies.get('access_token')
    header_data = {'Authorization': 'Bearer ' + token}
    response = requests.get('https://l339s04yk5.execute-api.us-east-1.amazonaws.com/test/member', headers=header_data).content
    return response


@application.route('/test')
def test():
    auth = request.headers.get('Authorization')
    return auth


@application.route('/callback')
def callback() -> Response:
    return render_template('home.html')

@application.route('/login')
def login() -> Response:
    return render_template('login.html')


'''
@application.route('/login')
def login():
    url = 'https://member.aetna.com/appConfig/login/login.fcc'
    header_data = {'Host': 'member.aetna.com', 
    'Connection': 'keep-alive',
    'sec-ch-ua': '" Not;A Brand";v="99", "Google Chrome";v="91", "Chromium";v="91"',
    'sec-ch-ua-mobile': '?0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    'Origin': 'www.aetna.com', 
    'Content-Type': 'application/x-www-form-urlencoded',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-User': '?1',
    'Sec-Fetch_Dest': 'document',
    'Accept-Encoding': 'gzip, deflate, br', 
    'Accept-Language': 'en-US,en;q=0.9'}
    
    

    ts = int(time.time()) 

    response = requests.get(url, verify=False)
    cookie = response.cookies
    for key, val in cookie.items():
        print("%s:%s" % (key, val))
    
    url = 'https://member.aetna.com/appConfig/login/js/loadLoginPage.js?v=%s' % (ts.__str__())
    response = requests.get(url, verify=False, cookies=cookie, headers=header_data)
    content = response.content
    
    matchs = re.findall(r"https://apih1\.aetna\.com.*?\"", str(content))
    url = matchs[0][:-1]
    print(url)

    
    my_cookie = {"visid_incap_2376121":"B/ejwM/MSwi/5xq7HwQ7kgbe3WAAAAAAQUIPAAAAAAA+UbV0r4X3JTtBzfuwYHTm",
    "AMCVS_993B1C8B532962CD0A490D4D%40AdobeOrg":'1',
    "SMSESSION":'LOGGEDOFF',
    "TLAETGuid":"6D496F88BED0CBB4FB6891F890985133",
    "AETAdnscc":'081fa51cc9ab28005a2bc50e57c4c998b96983fe6aed5b1d9b4af00b01956d6ae6395c35ede1a974dfefa70990e3d4d1',
    "AETAdnsac":'08e32e20470c1000d060050745c3c8898991585b976d8725',
    "AETAdnfp": "08e32e20471018009eefa06164472ffee861f3724753965dc3a6e90809d83ef6",
    "AMCV_993B1C8B532962CD0A490D4D%40AdobeOrg": "-1712354808%7CMCIDTS%7C18815%7CMCMID%7C09595950025426674711061891539614229865%7CMCAAMLH-1626306254%7C7%7CMCAAMB-1626306254%7CRKhpRz8krg2tLO6pguXWp5olkAcUniQYPHaMWWgdJ3xzPWQmdj0y%7CMCOPTOUT-1625708654s%7CNONE%7CvVersion%7C4.3.0%7CMCAID%7CNONE",
    "AETAdnrc": "08e32e20470a10000de3a12530ebfd32e0b4f519a91888da",
    "AETAdnuc": "08e32e2047063800be31d6c8ecb58645fd56a3af2f7d3eb39b05b4560aef621a8e255c0aad122cf61317e3188ef25408059e5d417943bf26c2963847b89d010b",
    "AETAdnmgc": "08e32e20470d180057e7d440c4ee421f5a80f0128c20e34a37877f205c51a28f",
    "AETAdnedc": "08e32e2047021000cbb3556565599fc0c168767bec59448f",
    "AETAdncsc2": "08e32e2047058800380370c0eb7a1b479beb73ddb414e4a5ad2867a81dc89ea515cb72250e9e573eceda18a381b34f8b1eda7df70cbf1e648c185ca4916feafad6422b21e7378c34a91e538835b384cb1dfe1cda42f5f638eaae6c43b1605668e435112a0c8bcabcea564e5033d1f72cb40f4fd55fac6763cd12d883313b655ce50daf6bf34525e0045fb712807ed2b4",
    "tp": "1152",
    "s_ppv": "am%253Aweb%253Alogin%253Asecure_member_login%2C88%2C88%2C1018",
    "s_ptc": "pt.rdr%240.20%5E%5Ept.apc%240.00%5E%5Ept.dns%240.00%5E%5Ept.tcp%240.00%5E%5Ept.req%240.15%5E%5Ept.rsp%240.06%5E%5Ept.prc%241.02%5E%5Ept.onl%240.01%5E%5Ept.tot%241.38%5E%5Ept.pfi%241",
    }
    header_data = {#'Host': 'apih1.aetna.com', 
    'Connection': 'keep-alive',
    'sec-ch-ua': '" Not;A Brand";v="99", "Google Chrome";v="91", "Chromium";v="91"',
    'sec-ch-ua-mobile': '?0',
    'Upgrade-Insecure-Requests': '1',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Sec-Fetch-Site': 'none',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-User': '?1',
    'Sec-Fetch_Dest': 'document',
    'Accept-Encoding': 'gzip, deflate, br', 
    'Accept-Language': 'en-US,en;q=0.9'}
    response = requests.get(url, cookies=my_cookie, headers=header_data, verify=False, allow_redirects=False)
    print(response.status_code)


    login_url = response.headers['location']
    print(login_url)
    #response = requests.get(login_url, cookies=my_cookie, headers=header_data, verify=False)

    path = '/Users/yefengwu/Nayya/test_s/lib/patched_chromedriver'
    #delay = 5 # seconds
    browser = webdriver.Chrome(path)
    browser.get(login_url)
    
    
    post_url = 'https://www.aetna.com/AccountManagerV3/v/login?signInClicked=0.49526489177400856'
    header_data = {#'Host': 'apih1.aetna.com', 
    'Connection': 'keep-alive',
    'sec-ch-ua': '" Not;A Brand";v="99", "Google Chrome";v="91", "Chromium";v="91"',
    'sec-ch-ua-mobile': '?0',
    'Upgrade-Insecure-Requests': '1',
    'Origin': 'https://www.aetna.com',
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Sec-Fetch-Site': 'same-origin',
    'Sec-Fetch-Mode': 'navigate',
    'Sec-Fetch-User': '?1',
    'Sec-Fetch_Dest': 'document',
    'Referer': login_url,
    'Accept-Encoding': 'gzip, deflate, br', 
    'Accept-Language': 'en-US,en;q=0.9'}

    my_cookie['redirectHome'] = '/individuals-families.html'
    my_cookie['first-pagevisit'] = 'true'
    #my_cookie['sessionId'] = 'true'
    my_cookie['s_pv_pn'] = 'ae:about-us:login'
    my_cookie['s_pv_lt'] = '0.59'
    my_cookie['ODRSESSIONCC_EXT1'] = response.cookies['ODRSESSIONCC_EXT1']
    my_cookie['JSESSIONID_106'] = response.cookies['JSESSIONID_106']

    
    form_data = {'username': 'cclukey81', 'Password': '1Puppydog',
    'skin': 'includes/css/skin0', 'channel': 'web', 'appName': 'NAV'}
    
    #response = requests.post(post_url, data=form_data, headers=header_data, verify=False, allow_redirects=False)
    
    return "Login"
'''

'''
@application.route('/aetna')
def aetna() :
    header_data = {'Host': 'www.aetna.com', 
    'Origin': 'www.aetna.com', 
    'Content-Type': 'application/x-www-form-urlencoded',
    'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
    'Accept-Encoding': 'gzip, deflate, br', 
    'Accept-Language': 'en-US,en;q=0.9'}
    
    url = 'https://www.aetna.com/AccountManagerV3/v/login?signInClicked=0.5192950571708412'
    #url = 'https://www.aetna.com/AccountManagerV3/v/login'
    form_data = {'username': 'cclukey81', 'Password': '1Puppydog',
    'secretString': 'p/66Qd+qEa25WJurnp5/FpDC1IITPymwPDeH15O06KZJYyhwLdMzj2jw5pLJxrw2ZpaeylAXc2kTl8fq3SdbVPWJnTb0H0JzDOlWZ/7i/da1i5HV7YgAt1/aSLZ7ybEtG5acKDJg9ljzOKtd7KyjKU7ulFFRq2ssjIu3V0G4GnC+/gdozNj5hAduXlZy/ogpX//vOj0iGcOAdxygkUy4YB5VNK+lBo5Pc7pY3Ltdlh53Yj44olC5tojt+UTRUWcqIGhH75ALiQ30WbdR8aWycjJXTpVsHsHdMWlNiaoqvNVO9nceNEyOF/d5fyqIpEcJwgeWqorLqT0D6BGlbLiOclg8MS2lz4V74eLZW+s6i9igRp/uqNMUnAnir5NTJZw91DusH4cIt0b4+SJ41N6MPsMr5JUbLVwbV7HoHp0YKpZzrwgjR4SpXKqetV1ARW88nFd91ETq489Hn7jht/AQ2rew+cw5/42PaQkR8BHJqQaPDS9BCLrjn9m+uIKwWDAph+Qleoe29FsMHoOp2ITV87TvbGrWBred5r4ExFNhp4a4Geeccw80SLWJvqZCNZyrC4tB0h/P5DWTsVen2vEdPiOQ53BCNygTUBjmSWIvFYRwEYFpMwQ2azqdUlMo7mVZvepzgipAW0bsM1yT0aiig3vq8DVGH4wB0s1jfYKXE/rIU+6X4Jm9ntLrthTMKA34',
    'skin': 'includes/css/skin0', 'channel': 'web', 'appName': 'NAV'}
    
    response = requests.post(url, data=form_data, headers=header_data, verify=False)#cert='www-aetna-com.pem')
    
    i = 1
'''    
if __name__ == "__main__":
    application.run()