---
name: Hunting License (2023)
event: HackTheBox Cyber Apocalypse - Intergalactic Chase CTF 2023
category: Rev
description: Writeup for Hunting License (Rev) - HackTheBox Cyber Apocalypse - Intergalactic Chase CTF (2023) 💜
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

# Hunting License

## Description

> STOP! Adventurer, have you got an up to date relic hunting license? If you don't, you'll need to take the exam again before you'll be allowed passage into the spacelanes!

## Solution

Used `ltrace` and find the first password.

{% code overflow="wrap" %}
```bash
strcmp("420", "PasswordNumeroUno")
```
{% endcode %}

Try again..

{% code overflow="wrap" %}
```bash
strcmp("420", "P4ssw0rdTw0")
```
{% endcode %}

Finally..

{% code overflow="wrap" %}
```bash
strcmp("420", "ThirdAndFinal!!!")
```
{% endcode %}

Remote server has additional questions, we can find answers easily with tools like `file`, `ldd`, `GDB` and `ghidra`.

{% code overflow="wrap" %}
```bash
nc 209.97.189.63 30590

What is the file format of the executable?
> elf
[+] Correct!

What is the CPU architecture of the executable?
> x86-64
[+] Correct!

What library is used to read lines for user answers? (`ldd` may help)
> libreadline.so.8
[+] Correct!

What is the address of the `main` function?
> 0x401172
[+] Correct!

How many calls to `puts` are there in `main`? (using a decompiler may help)
> 5
[+] Correct!

What is the first password?
> PasswordNumeroUno
[+] Correct!

What is the reversed form of the second password?
> 0wTdr0wss4P
[+] Correct!

What is the real second password?
> P4ssw0rdTw0
[+] Correct!

What is the XOR key used to encode the third password?
> 0x13
[+] Correct!

What is the third password?
> ThirdAndFinal!!!
[+] Correct!

[+] Here is the flag: `HTB{l1c3ns3_4cquir3d-hunt1ng_t1m3!}`
```
{% endcode %}

Flag: `HTB{l1c3ns3_4cquir3d-hunt1ng_t1m3!}`
