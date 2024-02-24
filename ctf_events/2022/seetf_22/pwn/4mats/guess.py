from pwn import *
from time import time
from ctypes import CDLL

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./vuln', checksec=False)

# Lib-C for rand()
libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')

# Create process (level used to reduce noise)
io = process(level='error')  # Local
# io = remote('fun.chall.seetf.sg', 50001)  # Remote

io.sendlineafter(b':', b'crypto')  # Submit name

io.sendlineafter(b'2. Do I know you?', b'1')  # Guess value

libc.srand(int(time()))  # Call srand() with current time as seed
guess = libc.rand() % 1000000  # Predict computers turn

io.sendlineafter(b'Guess my favourite number!', str(guess).encode())  # Submit guess

io.recvlines(2)
info(io.recv().decode())  # Print flag
