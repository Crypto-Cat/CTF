---
name: Free Flags (2021)
event: Angstrom CTF 2021
category: Rev
description: Writeup for Free Flags (Rev) - Angstrom CTF (2021) 💜
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

# Free Flags

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/MhkVkOpj5OI/0.jpg)](https://youtu.be/MhkVkOpj5OI?t=28s "Angstrom 2021: Free Flags")

## Challenge Description

> Clam was browsing armstrongctf.com when suddenly a popup appeared saying "GET YOUR FREE FLAGS HERE!!!" along with a download. Can you fill out the survey for free flags?

## Solution

{% code overflow="wrap" %}
```py
from pwn import *

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
exe = './free_flags_bin'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

io.sendlineafter('What number am I thinking of???', '31337')
io.sendlineafter('What two numbers am I thinking of???', '419\n723')
io.sendlineafter('What animal am I thinking of???', 'banana')
io.recvuntil("here's the FREE FLAG:\n")

# Get our flag!
flag = io.recv()
success(flag)
```
{% endcode %}

Flag: `actf{what_do_you_mean_bananas_arent_animals}`
