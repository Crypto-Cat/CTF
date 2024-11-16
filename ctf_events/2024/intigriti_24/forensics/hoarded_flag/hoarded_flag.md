---
name: Hoarded Flag (2024)
event: Intigriti 1337UP LIVE CTF 2024
category: Forensics
description: Writeup for Hoarded Flag (Forensics) - 1337UP LIVE CTF (2024) 💜
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

# Hoarded Flag

## Challenge Description

> My friend said they are going to make an insane new crypto challenge and I have to solve it but.. I hate crypto 😭

> I saw them making a flag but didn't catch the text. When they left room I tried to open the file but they password protected it?! I can't believe they wouldn't trust me around their computer like that!! 😤

> Anyway, I figured I'd take a snapshot to have a better look later.. Maybe you can help?

## Solution

-   Can analyse the memory dump with `volatility`
-   Check `cmdline` history and see a password with zip archive command: `python vol.py -f memory_dump.raw windows.cmdscan`
-   Get password `ScaredToDeathScaredToLook1312` and see the `flag.zip` and `flag.7z` files
-   Search for these files: `python vol.py -f memory_dump.raw windows.filescan | grep flag`
-   Download one of those (password for both is the same): `python vol.py -f memory_dump.raw windows.dumpfiles.DumpFiles --virtaddr 0xb20dbd74d5f0`
-   Extract the flag: `7z x flag.zip`

Flag: `INTIGRITI{7h3_m3m0ry_h0ld5_7h3_53cr375}`
