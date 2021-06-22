from flask import Flask

application = Flask(__name__)

@application.route('/')
def hello_world():
    return 'Hello World!!!'

"""
@app.route('/callback')
def hello() -> Response:
    token = request.args.get('access_token')
    import requests
    header_data = {'Authorize': token}
    response = requests.get('https://gyhot27101.execute-api.us-east-1.amazonaws.com/test/hello', headers=header_data).content
    return response
"""

if __name__ == "__main__":
    application.run()