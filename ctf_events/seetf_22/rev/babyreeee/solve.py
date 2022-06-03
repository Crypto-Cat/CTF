from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./chall', checksec=False)
context.log_level = 'debug'

# This prints out all of flag from .data section
#print(elf.data[0x20f0:(0x20f0 + (52 * 4))].hex())

# Encrypted flag, as extracted above - I just regexed out "00000"
enc_flag = unhex('988b88c371b67ea372bb737d7aa9747368a4b66e62bc616162b367bc616bb8b5565489558c505b5153545d5e50868989484f49f1')
dec_flag = ''

for i, enc_char in enumerate(enc_flag):
    # XOR current encrypted char with loop counter, then subtract 69
    dec_char = chr(int.from_bytes(xor(enc_char, i), 'little') - 69)
    debug(dec_char)
    dec_flag += dec_char

info(dec_flag)  # Print flag
