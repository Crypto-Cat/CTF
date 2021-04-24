from pwn import *

# phasestream1
ciphertext = unhex("2e313f2702184c5a0b1e321205550e03261b094d5c171f56011904")
key = xor(ciphertext[0:5], "CHTB{")
info("Phastream1 Key: %s", key)
plaintext = xor(ciphertext, key)
success('Phasestream1 Decrypted: %s', plaintext)
