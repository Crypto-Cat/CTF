---
name: Waiting an Eternity (2023)
event: Amateurs CTF 2023
category: Web
description: Writeup for Waiting an Eternity (Web) - Amateurs CTF (2023) 💜
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

# Waiting an Eternity

## Description

> My friend sent me this website and said that if I wait long enough, I could get and flag! Not that I need a flag or anything, but I've been waiting a couple days and it's still asking me to wait. I'm getting a little impatient, could you help me get the flag?

## Solution

We visit the challenge URL: https://waiting-an-eternity.amt.rs and see a message `just wait an eternity`.

There's nothing in the page source, cookies etc.

If we check the request in burp, there's a response header.

{% code overflow="wrap" %}
```bash
Refresh: 1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000; url=/secret-site?secretcode=5770011ff65738feaf0c1d009caffb035651bb8a7e16799a433a301c0756003a
```
{% endcode %}

OK, so let's visit https://waiting-an-eternity.amt.rs/secret-site?secretcode=5770011ff65738feaf0c1d009caffb035651bb8a7e16799a433a301c0756003a

We see another message `welcome. please wait another eternity`.

This time we do have a cookie, which is set in the HTTP response.

{% code overflow="wrap" %}
```bash
Set-Cookie: time=1689413881.7688985; Path=/
```
{% endcode %}

When we change the value to `999999999999999999999999999999999999999999999999999999999999999999999999999999999999` it says `you have not waited an eternity. you have only waited -1e+84 seconds`.

Increasing the number of `9`'s by like 10x results in a new message `you have not waited an eternity. you have only waited -inf seconds`.

Looking good! We've got infinite seconds, the problem is that it's a negative value.

Let's add a `-` before our `9`'s to reverse the sign.

We send the request and receive a flag.

Flag: `amateursCTF{im_g0iNg_2_s13Ep_foR_a_looo0ooO0oOooooOng_t1M3}`
