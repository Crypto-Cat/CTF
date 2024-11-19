---
name: IrrORversible (2024)
event: Intigriti 1337UP LIVE CTF 2024
category: Warmup
description: Writeup for IrrORversible (Warmup) - 1337UP LIVE CTF (2024) 💜
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

# IrrORversible

## Video walkthrough

[![VIDEO](https://img.youtube.com/vi/9NrmlOBcF1c/0.jpg)](https://youtu.be/9NrmlOBcF1c "Basic XOR encryption")

## Challenge Description

> So reversible it's practically irreversible

## Solution

Players can enter some text to encrypt.

![](./images/0.PNG)

As the challenge name hints, we should try some XOR operations.

Since XOR is reversible, having any two pieces of information will enable the recovery of the missing component, e.g. plaintext + key = ciphertext, ciphertext + key = plaintext, **plaintext + ciphertext = key**.

Note that the key is quite long, so you need to enter a sufficiently sized plaintext to [recover it all](<https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Latin1','string':'cryptocat%20is%20the%20best!%20'%7D,'Standard',false)&input=MmExYzU5MjgzYjNkNDMxNjExMDAxZDAxNTUwNzFjNDkwMDBjMGE1MzFhNDQ0NTA3NTIwZDFmNTQwOTBhMDYxYzU0NDU1MzYyMWQxYzE2MDAwNDA5MWEwNDAxNDEwZDE2NTkxNDE1MDEwMDA0NTgwMDAwMWQwMDEwMDkxYzAwMGQxNzUzMWE0ODQ3MGIwNjU3NTAyMDAwNDMwMjA2NDEwYTE4MDAwMDAwMGM1MzQyMGUxNjBkMGQwMDFhMWQwYzUwMTkxYTEwMTU1NDQ1MTEwMzRjMWIxYTAwMGM0MjJjM2QyMDY4NjczMTNiMmQzOTBmMGQ1NzU0NDU0MzM2MGIxMDA2MzcxMjQ4NTY1MjRjMDkwZDAwMGIxYjFkMTQxMTAxNDMwMDAwMDAwMDA3NTM1NDBiMGE1MjA3NGI1MzI3NDk0OTA1MDY1OTExMWEwYjQzMTUwMzQ5MWEwNzBjNTQxYzBkNTIwZDEwMTQxYzAxNDIwYTA2MGE1MDEzMGUwZjBlMDY0NTQ1NTM2ZjFhMDQxYzAwMTYwZDE2NTQ0MzUyMDIwNDFjNTAwMzA2MGYwZDU0NTMwNjFmNTYxMTQ4M2Q2ZjMwNDIwMDU0NGQ0ZjExMTc1NzM5MWE0ZjNiMmUyNjAwMWUxNjAwMDAxYTEwNTMxNjQ5NTMxYTRlMmE>).

Flag: `INTIGRITI{b451c_x0r_wh47?}`
