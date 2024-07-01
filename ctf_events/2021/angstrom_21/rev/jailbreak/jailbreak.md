---
name: Jail Break (2021)
event: Angstrom CTF 2021
category: Rev
description: Writeup for Jail Break (Rev) - Angstrom CTF (2021) 💜
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

# Jail Break

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/MhkVkOpj5OI/0.jpg)](https://youtu.be/MhkVkOpj5OI?t=433s "Angstrom 2021: Jail Break")

## Challenge Description

> Clam was arguing with kmh about whether including 20 pyjails in a ctf is really a good idea, and kmh got fed up and locked clam in a jail with a python! Can you help clam escape?

## Solution

{% code overflow="wrap" %}
```py
from pwn import *

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
breakrva 0x1313
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './jailbreak'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

# Give commands in correct order so that bVar1 == false
io.sendlineafter('What would you like to do?', 'pick the snake up')
io.sendlineafter('What would you like to do?', 'throw the snake at kmh')

# Now we need iVar7 == 1
io.sendlineafter('What would you like to do?', 'pry the bars open')

# Move into desired code block
io.sendlineafter('What would you like to do?', 'look around')

# Now we can press buttons (need to make iVar7 == 1337, it currently == 1)
# Red button will do iVar7 * 2
# Green button will do iVar7 * 2 + 1
io.sendlineafter('What would you like to do?', 'press the red button')  # 1 * 2 = 2
io.sendlineafter('What would you like to do?', 'press the green button')  # 2 * 2 + 1 = 5
io.sendlineafter('What would you like to do?', 'press the red button')  # 5 * 2 = 10
io.sendlineafter('What would you like to do?', 'press the red button')  # 10 * 2 = 20
io.sendlineafter('What would you like to do?', 'press the green button')  # 20 * 2 + 1 = 41
io.sendlineafter('What would you like to do?', 'press the green button')  # 41 * 2 + 1 = 83
io.sendlineafter('What would you like to do?', 'press the green button')  # 83 * 2 + 1 = 167
io.sendlineafter('What would you like to do?', 'press the red button')  # 167 * 2 = 334
io.sendlineafter('What would you like to do?', 'press the red button')  # 334 * 2 = 668
io.sendlineafter('What would you like to do?', 'press the green button')  # 668 * 2 + 1 = 1337

# Now we need to enter the password to get flag
io.sendlineafter('What would you like to do?', 'bananarama')
io.recvlines(2)

# Get our flag!
flag = io.recvline()
success(flag)
```
{% endcode %}

Flag: `actf{guess_kmh_still_has_unintended_solutions}`
