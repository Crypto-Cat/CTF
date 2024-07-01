---
name: Alien Camp (2021)
event: HackTheBox Cyber Apocalypse CTF 2021
category: Misc
description: Writeup for Alien Camp (Misc) - HackTheBox Cyber Apocalypse CTF (2021) 💜
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

# Alien Camp

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/3hP158TJk84/0.jpg)](https://youtu.be/3hP158TJk84?t=28s "HTB Cyber Apocalypse CTF 2021: Alien Camp")

## Challenge Description

> The Ministry of Galactic Defense now accepts human applicants for their specialised warrior unit, in exchange for their debt to be erased. We do not want to subject our people to this training and to be used as pawns in their little games. We need you to answer 500 of their questions to pass their test and take them down from the inside.

## Solution

{% code overflow="wrap" %}
```py
from pwn import *
import re

def get_mappings(p):
    # Get a little help
    p.sendlineafter('>', '1')
    p.recvlines(2)
    # Regex to extract unicode char mappings
    char_mappings = re.findall(r'(. -> \d+)', p.recvuntil('\n').decode(), re.UNICODE)
    # Now put them into dictionary
    mapping_dictionary = {}
    for mapping in char_mappings:
        split_mapping = mapping.split(' -> ')
        mapping_dictionary[split_mapping[0]] = split_mapping[1]
    return mapping_dictionary

def take_test(p, mapping_dictionary):
    p.recvuntil(':\n\n')

    # Extract question
    question = p.recvline().decode().strip()
    info('Unmapped question: %s', question)

    # Replace mappings with correct values
    mapped_question = ''.join(mapping_dictionary.get(char, char) for char in question)
    info('Mapped question: %s', mapped_question)

    # Perform equations
    answer = eval(mapped_question.split('=')[0])
    info('Answer: %s', answer)

    p.sendlineafter(':', str(answer))
    confirmation = p.recvlinesS(3)
    info('%s, Result: %s', confirmation[1], confirmation[2])

# Connect to AlienSpeak server
p = remote('138.68.185.219', '31990')
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'

# Get the char mappings
mapping_dictionary = get_mappings(p)

# Take a test
p.sendlineafter('>', '2')

# Take test 500 times
for i in range(500):
    take_test(p, mapping_dictionary)

# Flag?
success('Flag: %s', re.search(r'CHTB{.*}', p.recv().decode()).group(0))
```
{% endcode %}

Flag: `CHTB{3v3n_4l13n5_u53_3m0j15_t0_c0mmun1c4t3}`
