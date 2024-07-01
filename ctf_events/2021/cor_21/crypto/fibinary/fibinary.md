---
name: Fibinary (2021)
event: Crusaders of Rust (cor) CTF 2021
category: Crypto
description: Writeup for Fibinary (Crypto) - Crusaders of Rust (cor) CTF (2021) 💜
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

# Fibinary

## Challenge Description

> Warmup your crypto skills with the superior number system!

## Solution

{% code overflow="wrap" %}
```py
# first 11 numbers in fibonacci sequence (excl zero) - will be used by c2f()
fib = [1, 1]
for i in range(2, 11):
    fib.append(fib[i - 1] + fib[i - 2])
print('fib: ' + str(fib))

def c2f(c):
    n = ord(c)
    b = ''
    # looping from 10 to 0 (reverse order through fib)
    for i in range(10, -1, -1):
        # if our char is greater than current fib[i]
        if n >= fib[i]:
            # subtract fib[i] from char and add '1' to binary
            n -= fib[i]
            b += '1'
        else:
            # if char is smaller, add '0' to binary
            b += '0'
    return b

flag = 'fake_flag'
enc = ''
# perform encryption on fake flag and print
for c in flag:
    enc += c2f(c) + ' '
print('encrypted: ' + str(enc.strip()))

# OK so lets add a decrypt function..
def f2c(b):
    c = 0
    # loop through byte, incrementing by fib[i] when '1' is found
    for i in range(10, -1, -1):
        if b[i] == '1':
            c += fib[i]
    return chr(c)

dec = ''

# loop through the bytes, decrypting each one and returning char
for b in str(enc.strip()).split(" "):
    dec += f2c(b[::-1])  # reverse the byte

print('decrypted: ' + dec)
```
{% endcode %}

Flag: `corctf{b4s3d_4nd_f1bp!113d}`
