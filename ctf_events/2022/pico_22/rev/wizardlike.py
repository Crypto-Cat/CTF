from pwn import *

# Load our binary
exe = 'game'
elf = context.binary = ELF(exe, checksec=False)

# Patch out the call curs_set (annoying)
elf.asm(elf.symbols.curs_set, 'ret')

# Save the patched binary
elf.save('patched')

'''
Use these commands in terminal, to patch other instructions
(I'm not sure how to do this within pwntools, if you know - please tell me xD)

# Make map visible
pwn elfpatch game 1dba 00 > temp

# Walk through walls
pwn elfpatch temp 1657 01 > patched
'''
