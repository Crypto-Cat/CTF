import base64
import pickle
from flask import Flask, send_file, request, make_response, redirect
import random
import os

app = Flask(__name__)


flag = os.environ.get('FLAG', 'actf{FAKE_FLAG}')


@app.route('/pickle.jpg')
def bg():
    return send_file('pickle.jpg')


@app.route('/')
def jar():
    contents = request.cookies.get('contents')
    if contents:
        items = pickle.loads(base64.b64decode(contents))
    else:
        items = []
    return '<form method="post" action="/add" style="text-align: center; width: 100%"><input type="text" name="item" placeholder="Item"><button>Add Item</button><img style="width: 100%; height: 100%" src="/pickle.jpg">' + \
        ''.join(f'<div style="background-color: white; font-size: 3em; position: absolute; top: {random.random()*100}%; left: {random.random()*100}%;">{item}</div>' for item in items)


@app.route('/add', methods=['POST'])
def add():
    contents = request.cookies.get('contents')
    if contents:
        items = pickle.loads(base64.b64decode(contents))
    else:
        items = []
    items.append(request.form['item'])
    response = make_response(redirect('/'))
    response.set_cookie('contents', base64.b64encode(pickle.dumps(items)))
    return response


app.run(threaded=True, host="0.0.0.0")
