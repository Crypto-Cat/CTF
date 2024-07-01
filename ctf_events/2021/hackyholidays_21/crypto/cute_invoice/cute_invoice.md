---
name: Cute Invoice (2021)
event: Hacky Holidays Space Race CTF 2021
category: Crypto
description: Writeup for Cute Invoice (Crypto) - Hacky Holidays Space Race CTF (2021) 💜
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

# Cute Invoice

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/u1Sh5TZN5Ug/0.jpg)](https://youtu.be/u1Sh5TZN5Ug?t=2292s "Hacky Holidays Space Race 2021: Cute Invoice")

## Challenge Description

> Who knew invoices could be secure AND cute? Our third-party contractor for space shuttle parts is using the best tooling for sending us secure invoices.

## Solution

{% code overflow="wrap" %}
```py
from pikepdf import Pdf
from PySide6 import QtCore

# https://github.com/IJHack/QtPass/blob/master/src/passwordconfiguration.h shows charset
charset = list('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890~!@#$%^&*()_-+={}[]|:;<>,.?')
password_len = 16  # Screeshot shows 16

# https://github.com/IJHack/QtPass/issues/338
# QTime::msec indicates this is merely "the millisecond part (0 to 999) of the time", e.g. only 1000 possibilities of generated sequences of passwords
for x in range(1, 1000):
    password = ''

    # https://www.cplusplus.com/reference/random/minstd_rand/
    # The generator has a single value as state, which is modified by its transition algorithm on each advance like x is modified in the following piece of code:
    # x = x * 48271 % 214748364
    state = x * 48271 % 2147483647
    for i in range(password_len):
        index = state % len(charset)  # int index = Util::rand() % charset.length();
        nextChar = charset[index]  # QChar nextChar = charset.at(index);
        password += str(nextChar)  # passwd.append(nextChar);
        state = state * 48271 % 2147483647

    try:
        # Try to open PDF with this password, print if correct
        pdf = Pdf.open('invoice.pdf', password=str(password))
        print('correct password: ' + str(password))
        print(pdf)
        exit(0)
    except Exception as e:
        print('incorrect password: ' + str(password))
```
{% endcode %}
