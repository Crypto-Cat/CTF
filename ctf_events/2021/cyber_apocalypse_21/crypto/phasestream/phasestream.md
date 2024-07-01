---
name: PhaseStream1 (2021)
event: HackTheBox Cyber Apocalypse CTF 2021
category: Crypto
description: Writeup for PhaseStream1 (Crypto) - HackTheBox Cyber Apocalypse CTF (2021) 💜
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

# PhaseStream1

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/Wku6uEOAGIc/0.jpg)](https://youtu.be/Wku6uEOAGIc?t=108s "HTB Cyber Apocalypse CTF 2021: PhaseStream1")

## Challenge Description

> The aliens are trying to build a secure cipher to encrypt all our games called "PhaseStream". They've heard that stream ciphers are pretty good. The aliens have learned of the XOR operation which is used to encrypt a plaintext with a key. They believe that XOR using a reapeted 5-byte key is enough to build a strong stream cipher. Such silly aliens! Here's a flag they encrypted this way earlier. Can you decrypt it (hint: what's the flag format?) 2e313f2702184c5a0b1e321205550e03261b094d5c171f56011904

## Solution

{% code overflow="wrap" %}
```py
from pwn import *

# phasestream1
ciphertext = unhex("2e313f2702184c5a0b1e321205550e03261b094d5c171f56011904")
key = xor(ciphertext[0:5], "CHTB{")
info("Phastream1 Key: %s", key)
plaintext = xor(ciphertext, key)
success('Phasestream1 Decrypted: %s', plaintext)
```
{% endcode %}

Flag: `CHTB{u51ng_kn0wn_pl41nt3xt}`
