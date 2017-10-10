from flask import Flask
import socket

application = Flask(__name__)

@application.route("/")
def hello():
    html = "<h3>Hello World from {host}!</h3>"
    return html.format(host=socket.gethostname())

if __name__ == "__main__":
    application.run(host='0.0.0.0')
