---
name: Intercept (2021)
event: HackTheBox Cyber Apocalypse CTF 2021
category: Rev
description: Writeup for Intercept (Rev) - HackTheBox Cyber Apocalypse CTF (2021) 💜
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

# Intercept

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/3GGpyEkt8GE/0.jpg)](https://youtu.be/3GGpyEkt8GE?t=2206s "HTB Cyber Apocalypse CTF 2021: Intercept")

## Challenge Description

> Intercept We managed to covertly spy on some of the elves' communications, as well as obtain partial code for their experimental encryption algorithm. Can you find where they're planning their next meeting?

## Solution

{% code overflow="wrap" %}
```py
from pwn import *

enc = unhex(b'5b2fedd4801914e7eb765119d4fe6223f1d1984638a9816b5419dac07b27eed9d35e09fdef65521ac5877a24eed19b0c0ae9f16d4c02cc86773bfaa8924a2ae9a12a2f1dd7923d39eea78d5909f9f57b2a16ddc87d33ada58f1208d4f737755283da1168a3e6cc075e8ce920774ef88d483fb1bb8a440884af7d69e2c5874b3bb3be695d4fd5a97b27e7d7d0572cf0bf665405dbfe4225e19b824813e4b96a4e178a95776fe1d8800b0bf7f0705719c0c37834a8f7a26f1febbe3d7119dad66427d5f58b4259eabc3f3626ded46621d3b0ca441afce552274bd6da1f2a')

dec = b''

for i, byte in enumerate(enc):
    dec += xor(chr((55 * i + 19) % 256), byte)

success(dec.decode())
```
{% endcode %}

Flag: ` HTB{pl41nt3xt_4sm?wh4t_n3xt_s0urc3_c0d3?}`
