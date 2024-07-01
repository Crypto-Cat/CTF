---
name: Side Channel (2022)
event: Pico CTF 2022
category: Forensics
description: Writeup for Side Channel (Forensics) - Pico CTF (2022) 💜
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

# Side Channel

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/V_Hm6P00IwU/0.jpg)](https://youtu.be/V_Hm6P00IwU?t=1344 "Pico CTF 2022: Side Channel")

## Description

> There’s something fishy about this PIN-code checker, can you figure out the PIN and get the flag?

## Solution

{% code overflow="wrap" %}
```py
import time
from pwn import *

chars = "0123456789"
pin_len = 8
current_pin = ""

for pos in range(pin_len):  # loop 8 digit pin
    max_time = 0
    correct_num = ""
    for i in list(chars):  # loop charset (0-9)
        io = process('./pin_checker', level='warn')

        this_iteration = current_pin + i + ("0" * (pin_len - len(current_pin) - 1))
        # measure time taken for response
        start = time.time()
        io.sendlineafter(b":", this_iteration.encode())
        io.recvlines(3)
        result = io.recvline()
        stop = time.time()
        time_taken = stop - start

        # is this the longest response time yet?
        if time_taken > max_time:
            max_time = time_taken
            correct_num = i

        log.info(f"Pin submitted: {this_iteration}")
        # log.info(f"Received answer: {result.decode()}")
        log.info(f"Time taken: {time_taken}")

    # add correct char to final pin
    print()
    log.info(f"Max time: {max_time}")
    log.info(f"Correct num: {correct_num}")
    current_pin += correct_num
    print()

log.info(f"Correct pin: {current_pin}")
```
{% endcode %}
