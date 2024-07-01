---
name: Split (2021)
event: HackTheBox x Synack RedTeamFive CTF 2021
category: Rev
description: Writeup for Split (rev) - HackTheBox x Synack RedTeamFive CTF (2021) 💜
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

# Split

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/TN1zPbKN_9E/0.jpg)](https://youtu.be/TN1zPbKN_9E?t=585s "HackTheBox x Synack RedTeamFive 2021: Split")

## Solution

#### backdoor.py

{% code overflow="wrap" %}
```py
from pwn import *

# Load our binary
exe = 'split'
elf = context.binary = ELF(exe, checksec=False)

# Patch out the call to ptrace ;)
elf.asm(elf.symbols.ptrace, 'ret')

# Save the patched binary
elf.save('patched')
```
{% endcode %}
