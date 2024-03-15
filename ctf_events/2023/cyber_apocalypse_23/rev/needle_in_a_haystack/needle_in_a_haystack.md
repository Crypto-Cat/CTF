---
name: Needle in a Haystack (2023)
event: HackTheBox Cyber Apocalypse - Intergalactic Chase CTF 2023
category: Rev
description: Writeup for Needle in a Haystack (Rev) - HackTheBox Cyber Apocalypse - Intergalactic Chase CTF (2023) 💜
layout:
    title:
        visible: true
    description:
        visible: true
    tableOfContents:
        visible: false
    outline:
        visible: true
    pagination:
        visible: true
---

# Needle in a Haystack

## Description

> You've obtained an ancient alien Datasphere, containing categorized and sorted recordings of every word in the forgotten intergalactic common language. Hidden within it is the password to a tomb, but the sphere has been worn with age and the search function no longer works, only playing random recordings. You don't have time to search through every recording - can you crack it open and extract the answer?

## Solution

Uses `time(0)` and `rand` and a big array of words. Used some chatGPT to convert code to python but then realised we can just break in GDB where the words are loaded and check the results, e.g.

```bash
breakrva 0x224b
```

Then either print words and manually search:

```bash
x/203s 0x555555557008
```

Alternatively, search with GDB:

```bash
search "HTB"
Searching for value: 'HTB'
haystack        0x555555557418 'HTB{d1v1ng_1nt0_th3_d4tab4nk5}'
haystack        0x555555558418 'HTB{d1v1ng_1nt0_th3_d4tab4nk5}'
```

Flag: `HTB{d1v1ng_1nt0_th3_d4tab4nk5}`
