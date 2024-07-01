---
name: Injection Traffic (2021)
event: Hacky Holidays Space Race CTF 2021
category: Forensics
description: Writeup for Injection Traffic (Forensics) - Hacky Holidays Space Race CTF (2021) 💜
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

# Injection Traffic

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/u1Sh5TZN5Ug/0.jpg)](https://youtu.be/u1Sh5TZN5Ug?t=435s "Hacky Holidays Space Race 2021: Injection Traffic")

## Challenge Description

> Help us run forensics on this database exploit…

## Solution

{% code overflow="wrap" %}
```py
from pyshark import *
import re

capture = FileCapture('traffic.pcap')

# Fake flag will be updated as pcap processed
flag = list("CTF{deadbeefdeadc0dedeadbeefdeadc0de}")

for i, packet in enumerate(capture):
    try:
        # Grab SQL queries
        sql_query = packet.tds.query
        if 'SUBSTRING' in sql_query:
            # If the response length is 200 then condition is true
            if capture[i + 1].length == '200':
                # Extract the char position and decimal value
                extracted = re.match(r'.*,(\d+),\d+\)\)\>(\d+)', sql_query, re.M | re.I)
                char_index = extracted.group(1)
                char_value = extracted.group(2)
                # Update the flag
                flag[int(char_index) - 1] = chr(int(char_value) + 1)
    except AttributeError as e:
        pass

# Profit?
print(''.join(flag))
```
{% endcode %}
