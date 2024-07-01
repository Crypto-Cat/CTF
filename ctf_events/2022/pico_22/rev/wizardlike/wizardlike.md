---
name: Wizardlike (2022)
event: Pico CTF 2022
category: Rev
description: Writeup for Wizardlike (Rev) - Pico CTF (2022) 💜
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

# Wizardlike

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/l6Lt1sWZOUU/0.jpg)](https://youtu.be/l6Lt1sWZOUU?t=1101 "Pico CTF 2022: Wizardlike")

## Description

> Do you seek your destiny in these deplorable dungeons? If so, you may want to look elsewhere. Many have gone before you and honestly, they've cleared out the place of all monsters, ne'erdowells, bandits and every other sort of evil foe. The dungeons themselves have seen better days too. There's a lot of missing floors and key passages blocked off. You'd have to be a real wizard to make any progress in this sorry excuse for a dungeon!

## Solution

{% code overflow="wrap" %}
```py
from pwn import *

# Load our binary
exe = 'game'
elf = context.binary = ELF(exe, checksec=False)

# Patch out the call curs_set (annoying)
elf.asm(elf.symbols.curs_set, 'ret')

# Save the patched binary
elf.save('patched')

'''
Use these commands in terminal, to patch other instructions
(I'm not sure how to do this within pwntools, if you know - please tell me xD)

# Make map visible
pwn elfpatch game 1dba 00 > temp

# Walk through walls
pwn elfpatch temp 1657 01 > patched
'''
```
{% endcode %}
