from pwn import *

# Load our binary
exe = 'challenge'
elf = context.binary = ELF(exe, checksec=False)

# Patch out the call to ptrace ;)
elf.asm(elf.symbols.ptrace, 'ret')

# Save the patched binary
elf.save('patched')
