---
name: Twizzty Buzzinezz (2021)
event: K3RN3L CTF 2021
category: Crypto
description: Writeup for Twizzty Buzzinezz (crypto) - K3RN3L CTF (2021) 💜
layout:
    title:
        visible: true
    description:
        visible: true
    tableOfContents:
        visible: true
    outline:
        visible: true
    pagination:
        visible: true
---

# Twizzty Buzzinezz

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/jSyLy_SfoyQ/0.jpg)](https://youtu.be/jSyLy_SfoyQ "K3RN3L 2021: Twizzty Buzzinezz")

## Challenge Description

> Some bees convinced me to invest in their new cryptosystem. They said their new XOR keystream would revolutionize the crypto market. However, they quickly buzzed away so all I have is this weird flyer they dropped. Luckily it has some source code on the back." "Have I just really been scammed by some bees??
>
> Encrypted Flag: 632a0c6d68a7e5683601394c4be457190f7f7e4ca3343205323e4ca072773c177e6e

## Solution

{% code overflow="wrap" %}
```py
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
```
{% endcode %}

Flag: `flag{s1mpl3_X0R_but_w1th_4_tw1zzt}`
