---
name: Checker (2021)
event: CSAW CTF 2021
category: Rev
description: Writeup for Checker (rev) - CSAW CTF (2021) 💜
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

# Checker

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/1Dw21NoxXjE/0.jpg)](https://youtu.be/1Dw21NoxXjE?t=953s "CSAW 2021: Checker")

## Challenge Description

> What's up with all the zeros and ones? Where are my letters and numbers?

## Solution

{% code overflow="wrap" %}
```py
def up(x):
    x = [f"{ord(x[i]) << 1:08b}" for i in range(len(x))]
    return ''.join(x)

def down(x):
    x = ''.join(['1' if x[i] == '0' else '0' for i in range(len(x))])
    return x

def right(x, d):
    x = x[d:] + x[0:d]
    return x

def left(x, d):
    x = right(x, len(x) - d)
    return x[::-1]

def encode(plain):
    d = 24
    print('init : 01100001011000100110001101100100')
    x = up(plain)
    print('up   : ' + x)
    x = right(x, d)
    print('right: ' + x)
    x = down(x)
    print('down : ' + x)
    x = left(x, d)
    print('left : ' + x)
    return x

def decode(encoded):
    d = 24
    x = right(encoded[::-1], d)
    x = down(x)
    x = right(x, len(encoded) - d)
    return x

def main():
    # For manual demo/calc
    # encoded = encode('abcd')

    flag = "1010000011111000101010101000001010100100110110001111111010001000100000101000111011000100101111011001100011011000101011001100100010011001110110001001000010001100101111001110010011001100"

    decoded = decode(flag)
    print(decoded)

    # need to go and bitshift right on result:
    # https://gchq.github.io/CyberChef/#recipe=From_Binary('Space',8)Bit_shift_right(1,'Logical%20shift')&input=MTEwMDExMDAxMTAxMTAwMDExMDAwMDEwMTEwMDExMTAxMTExMDExMDExMTAwMTAwMDExMDAxMTAxMTEwMTEwMDExMDAxMDEwMTExMDAxMDAxMTEwMDExMDAxMDAwMDEwMTEwMTExMDAxMDAwMTExMDEwMTExMTEwMTExMDExMTAxMDAwMDAwMDExMTAwMTAwMTEwMTEwMTAxMDExMTExMDEwMTAxMDEwMTExMDAwMDAxMTExMTAxMA

if __name__ == "__main__":
    main()
```
{% endcode %}

Flag: `flag{r3vers!nG_w@rm_Up}`
