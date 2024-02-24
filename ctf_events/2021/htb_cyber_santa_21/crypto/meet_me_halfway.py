from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from itertools import product
from pwn import *

alphabet = b'0123456789abcdef'
const = b'cyb3rXm45!@#'
pt = pad(b'cryptocat', 16)
ct = unhex('17de2b9f73ffa462c257c4a9fb29fe33')
encrypted_flag = unhex(
    'ac2ad0394dca2c79d15e55f24284b8e5')
win_prefix = b''
win_suffix = b''

# Key 1 (const + 4 random chars)
ciphertext_dict = {}
for i in product(alphabet, repeat=4):
    suffix = bytes(list(i))
    key1 = const + suffix
    cipher1 = AES.new(key=key1, mode=AES.MODE_ECB)
    c1 = cipher1.encrypt(pt)
    ciphertext_dict[c1] = suffix

# Key 2 (4 random chars + const)
for i in product(alphabet, repeat=4):
    prefix = bytes(list(i))
    key2 = prefix + const
    cipher2 = AES.new(key=key2, mode=AES.MODE_ECB)
    p1 = cipher2.decrypt(ct)
    if p1 in ciphertext_dict:
        print("Found {} {}".format(ciphertext_dict[p1], prefix))
        win_suffix = ciphertext_dict[p1]
        win_prefix = prefix

# Use our extracted key to solve the challenge!
key1 = const + win_suffix
key2 = win_prefix + const
c = AES.new(key=key2, mode=AES.MODE_ECB)
middle = c.decrypt(encrypted_flag)
c = AES.new(key=key1, mode=AES.MODE_ECB)
flag = c.decrypt(middle)
print('[+] FLAG {}'.format(flag))
