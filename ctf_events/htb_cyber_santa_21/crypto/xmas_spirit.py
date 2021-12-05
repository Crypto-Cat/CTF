import random
from math import gcd
from Crypto.Util.number import *
from pwn import *


# Original encrypt function
def encrypt(dt):
    mod = 256
    while True:
        a = random.randint(1, mod)
        if gcd(a, mod) == 1:
            break
    b = random.randint(1, mod)

    res = b''
    for byte in dt:
        enc = (a * byte + b) % mod
        res += bytes([enc])
    return res


# Our custom decrypt function
def decrypt(dt, a, b):
    res = b''
    # Reverse the encrypt operation
    for byte in dt:
        # Modular multiplicative inverse function - EAA (Euclidean)
        byte = (inverse(a, mod) * byte - b) % mod
        res += bytes([byte])
    return res


# http://mathcenter.oxford.emory.edu/site/math125/breakingAffineCiphers/
mod = 256  # Range of bytes
dt = read('encrypted.bin')
m = unhex('255044462D')  # Known Plaintext (PDF file header)

# Recover key (a, b) using known plaintext and ciphertext
# https://planetcalc.com/3311/
a = (dt[1] - dt[0]) * inverse(m[1] - m[0], mod) % mod
b = (dt[0] - a * m[0]) % mod

# Decrypt
res = decrypt(dt, a, b)
# Write back to PDF
write('decrypted.pdf', res)
