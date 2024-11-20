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

It's a memory dump, so we can analyse with [volatility](https://github.com/volatilityfoundation/volatility3)

Iterate through each of the plugins, looking for useful info. One of those plugins checks the `cmdline` and reveals some interesting command.

{% code overflow="wrap" %}
```bash
python vol.py -f memory_dump.raw windows.cmdscan

** 1032	conhost.exe	0x23442febbf0	_COMMAND_HISTORY.CommandBucket_Command_1	0x2344310e0e0	7z a -pScaredToDeathScaredToLook1312 -mhe flag.7z flag.zip
```
{% endcode %}

So, `7z` was used to encrypt a flag using the password `ScaredToDeathScaredToLook1312` 🤔

Search for these files with the `filescan` plugin.

{% code overflow="wrap" %}
```bash
python vol.py -f memory_dump.raw windows.filescan | grep flag

0xb20dbd74d5f0.0\Users\cat\Desktop\flag.zip
0xb20dbd74e720	\Users\cat\Desktop\flag.7z
```
{% endcode %}

Download one of those (password for both is the same)

{% code overflow="wrap" %}
```bash
python vol.py -f memory_dump.raw windows.dumpfiles.DumpFiles --virtaddr 0xb20dbd74e720
```
{% endcode %}

Finally, extract the flag: `7z x flag.zip`

Flag: `INTIGRITI{7h3_m3m0ry_h0ld5_7h3_53cr375}`
