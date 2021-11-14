import os
from pwn import *

FLAG = unhex('632a0c6d68a7e5683601394c4be457190f7f7e4ca3343205323e4ca072773c177e6e')


class HoneyComb:
    def __init__(self, key):
        self.vals = [i for i in key]

    def turn(self):
        self.vals = [self.vals[-1]] + self.vals[:-1]

    def encrypt(self, msg):
        keystream = []
        while len(keystream) < len(msg):
            keystream += self.vals
            self.turn()
        return bytes([msg[i] ^ keystream[i] for i in range(len(msg))])


# https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Latin1','string':'flag%7B'%7D,'Standard',false)To_Decimal('Comma',false)&input=NjMyYTBjNmQ2OA
for i in range(255):
    hc = HoneyComb(bytes([5, 70, 109, 10, 19, i]))
    print(hc.encrypt(FLAG))
