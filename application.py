from flask import Flask, request, render_template
from flask.wrappers import Response
import requests
import boto3
import os
import hmac
import hashlib
import base64


application = Flask(__name__)

CLIENT = boto3.client('cognito-idp')
USER_POOL_ID = 'us-east-1_bprylat5n'
CLIENT_ID = '7ark1101nfsj5l00n1bo28h2la'
CLIENT_SECRET = 'c43hs3qrk1d73unbjtj94d43fujv0grgja81rk3iup34i8qocqa'

@application.route('/cognito')
def cognito():
    #print(response)
    return get_user_token()
    

def get_user_token():
    username = 'aaa@aaa.com'
    password = '1qaz2wsx'
    
    try:
        resp = CLIENT.admin_initiate_auth(
            UserPoolId=USER_POOL_ID,
            ClientId=CLIENT_ID,
            AuthFlow='ADMIN_NO_SRP_AUTH',
            AuthParameters={
                'USERNAME': username,
                'SECRET_HASH': get_secret_hash(username),
                'PASSWORD': password
            },
            ClientMetadata={
                'username': username,
                'password': password
            })
        # print(resp)
    except CLIENT.exceptions.NotAuthorizedException:
        return False, "The username or password is incorrect."
    except CLIENT.exceptions.UserNotConfirmedException:
        return False, "User is not confirmed."
    except Exception as e:
        print(e)
        return False, str(e)
    if 'AuthenticationResult' in resp:
        token = {
            'IdToken': resp['AuthenticationResult']['IdToken'],
            'RefreshToken': resp['AuthenticationResult']['RefreshToken'],
            'AccessToken': resp['AuthenticationResult']['AccessToken']
        }
        # id_token = resp['AuthenticationResult']['IdToken']
        return token
    return resp

def get_secret_hash(username):
    msg = username + CLIENT_ID
    dig = hmac.new(str(CLIENT_SECRET).encode('utf-8'),
        msg = str(msg).encode('utf-8'), digestmod=hashlib.sha256).digest()
    d2 = base64.b64encode(dig).decode()
    return d2

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


if __name__ == "__main__":
    application.run()