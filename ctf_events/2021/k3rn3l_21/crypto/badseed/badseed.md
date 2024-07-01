---
name: Badseed (2021)
event: K3RN3L CTF 2021
category: Crypto
description: Writeup for Badseed (crypto) - K3RN3L CTF (2021) 💜
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

# Badseed

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/hlJFrZn87A/0.jpg)](https://youtu.be/hlJFrZn87A "K3RN3L 2021: Badseed")

## Challenge Description

> Learn how to interact with a process and solve the quiz.

## Solution

{% code overflow="wrap" %}
```py
from pwn import *
from time import time
from ctypes import CDLL

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
continue
'''.format(**locals())

# Binary filename
exe = './badseed'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

# Question 1 - let's do the sum
correct_answer = int(4000 / 6.035077)
io.sendlineafter('how heavy is an asian elephant on the moon?', str(correct_answer).encode())

# Question 2 - first we need to recreate time
libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')
current_time = int(time())
libc.srand(current_time)
libc.rand()
correct_answer = libc.rand()
io.sendlineafter('give me the rand() value', str(correct_answer).encode())

# Question 3 - need to recreate the equation again
current_time = int(time())
libc.srand(current_time)
rand_a = libc.rand()
libc.srand(rand_a)
rand_b = libc.rand()
correct_answer = int(rand_a / rand_b) % 1000
io.sendlineafter('no hint this time... you can do it?!', str(correct_answer).encode())

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `flag{i_0_w1th_pwn70ols_i5_3a5y}`
