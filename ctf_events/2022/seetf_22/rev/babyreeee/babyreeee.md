---
name: Baby Reeee (2022)
event: Social Engineering Experts CTF 2022
category: Rev
description: Writeup for Baby Reeee (Rev) - Social Engineering Experts CTF (2022) 💜
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

# Baby Reeee

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/-cc4U1H53F8/0.jpg)](https://youtu.be/-cc4U1H53F8?t=132 "Social Engineering Experts CTF 2022: Baby Reeee")

## Description

> You've never seen a flagchecker this helpful.

## Solution

{% code overflow="wrap" %}
```py
from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./chall', checksec=False)
context.log_level = 'debug'

# Encoded flag from .data section (offset found in GDB)
raw_flag = str(elf.data[0x20f0:(0x20f0 + (52 * 4))].hex())

# Each byte of flag stored in 4 byte, so remove 3 bytes of padding
enc_flag = unhex(raw_flag.replace('000000', ''))
dec_flag = ''

for i, enc_char in enumerate(enc_flag):
    # XOR current encrypted char with loop counter, then subtract 69
    dec_char = chr(int.from_bytes(xor(enc_char, i), 'little') - 69)
    debug(dec_char)
    dec_flag += dec_char

info(dec_flag)  # Print flag
```
{% endcode %}

Flag: `SEE{0n3_5m411_573p_81d215e8b81ae10f1c08168207fba396}`
