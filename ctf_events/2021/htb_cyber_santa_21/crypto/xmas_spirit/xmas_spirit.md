---
name: XMAS Spirit (2021)
event: HackTheBox Cyber Apocalypse CTF 2021
category: Crypto
description: Writeup for XMAS Spirit (Crypto) - HackTheBox Cyber Apocalypse CTF (2021) 💜
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

# XMAS Spirit

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/deg0CQwwN-M/0.jpg)](https://youtu.be/deg0CQwwN-M?t=764s "HTB Cyber Apocalypse CTF 2021: XMAS Spirit")

## Challenge Description

> XMAS Spirit Now that elves have taken over Santa has lost so many letters from kids all over the world. However, there is one kid who managed to locate Santa and sent him a letter. It seems like the XMAS spirit is so strong within this kid. He was so smart that thought of encrypting the letter in case elves captured it. Unfortunately, Santa has no idea about cryptography. Can you help him read the letter?

## Solution

{% code overflow="wrap" %}
```py
import random
from math import gcd
from Crypto.Util.number import *
from pwn import *

# Original encrypt function
def encrypt(dt):
    mod = 256
    while True:
        a = random.randint(1, mod)
        if gcd(a, mod) == 1:
            break
    b = random.randint(1, mod)

    res = b''
    for byte in dt:
        enc = (a * byte + b) % mod
        res += bytes([enc])
    return res

# Our custom decrypt function
def decrypt(dt, a, b):
    res = b''
    # Reverse the encrypt operation
    for byte in dt:
        # Modular multiplicative inverse function - EAA (Euclidean)
        byte = (inverse(a, mod) * byte - b) % mod
        res += bytes([byte])
    return res

# http://mathcenter.oxford.emory.edu/site/math125/breakingAffineCiphers/
mod = 256  # Range of bytes
dt = read('encrypted.bin')
m = unhex('255044462D')  # Known Plaintext (PDF file header)

# Recover key (a, b) using known plaintext and ciphertext
# https://planetcalc.com/3311/
a = (dt[1] - dt[0]) * inverse(m[1] - m[0], mod) % mod
b = (dt[0] - a * m[0]) % mod

# Decrypt
res = decrypt(dt, a, b)
# Write back to PDF
write('decrypted.pdf', res)
```
{% endcode %}

Flag: `HTB{4ff1n3_c1ph3r_15_51mpl3_m47h5}`
