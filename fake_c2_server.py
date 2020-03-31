# py -m pip install flask pyopenssl
# open \Windows\System32\drivers\etc\hosts -> add "127.0.0.1 proxy1-1-1.i2p"
# run py script before executing malware
from flask import Flask, escape, request


app = Flask(__name__)


@app.route('/qdanbh5iuf', methods=['GET', 'POST'])
def setup():
    print("Data Received:")
	print("-"*30)

    data = request.data
    #data = request.form[some_param] # only use if we know the dict being returned
    print(data)

    return 'None'


if __name__ == "__main__":
    app.run(ssl_context='adhoc', port=80)
