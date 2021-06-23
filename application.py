from flask import Flask, request, render_template
from flask.wrappers import Response
import requests


application = Flask(__name__)


@application.route('/')
def hello_world():
    return 'Hello World!!!'


@application.route('/healthy')
def healthy():
    return 'healthy'


@application.route('/api')
def api():
    token = request.cookies.get('access_token')
    header_data = {'Authorize': token}
    response = requests.get('https://gyhot27101.execute-api.us-east-1.amazonaws.com/test/hello', headers=header_data).content
    return response
    

@application.route('/callback')
def callback() -> Response:
    return render_template('home.html')


if __name__ == "__main__":
    application.run()