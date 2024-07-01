---
name: Infiltration (2021)
event: HackTheBox Cyber Apocalypse CTF 2021
category: Rev
description: Writeup for Infiltration (Rev) - HackTheBox Cyber Apocalypse CTF (2021) 💜
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

# Infiltration

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/20FkOdoMiRU/0.jpg)](https://youtu.be/20FkOdoMiRU?t=2492s "HTB Cyber Apocalypse CTF 2021: Infiltration")

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
breakrva 0x16a0
breakrva 0x1707
breakrva 0x1748
continue
'''.format(**locals())

# Binary filename
exe = './client'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

client = listen(1337)  # Setup listener on port 1337
io = start(['127.0.0.1', '1337'])  # Launch binary with localhost:1337
# Wait for the client to connect to the server
io = client.wait_for_connection()

# FOR TESTING - turns out solution was breakpoint/strace
io.send(b'HTB{0123456789abcdefghijklmnopq}')
print(io.recv())

io.send(b'HTB{0123456789abcdefghijklmnopq}')
print(io.recv())

io.send(b'1')

io.interactive()
```
{% endcode %}

Flag: `HTB{n0t_qu1t3_s0_0p4qu3}`
