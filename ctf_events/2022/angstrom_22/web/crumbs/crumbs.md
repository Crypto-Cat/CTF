---
name: Crumbs (2022)
event: Angstrom CTF 2022
category: Web
description: Writeup for Crumbs (Web) - Angstrom CTF (2022) 💜
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

# Crumbs

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/YmJoeoXilac/0.jpg)](https://youtu.be/YmJoeoXilac?t=718 "Angstrom CTF 2022: Crumbs")

## Description

> Follow the crumbs.

## Source

{% code overflow="wrap" %}
```js
const express = require("express");
const crypto = require("crypto");

const app = express();
const port = Number(process.env.PORT) || 8080;

const flag = process.env.FLAG || "actf{placeholder_flag}";

const paths = {};
let curr = crypto.randomUUID();
let first = curr;

for (let i = 0; i < 1000; ++i) {
    paths[curr] = crypto.randomUUID();
    curr = paths[curr];
}

paths[curr] = "flag";

app.use(express.urlencoded({ extended: false }));

app.get("/:slug", (req, res) => {
    if (paths[req.params.slug] === "flag") {
        res.status(200).type("text/plain").send(flag);
    } else if (paths[req.params.slug]) {
        res.status(200)
            .type("text/plain")
            .send(`Go to ${paths[req.params.slug]}`);
    } else {
        res.status(200).type("text/plain").send("Broke the trail of crumbs...");
    }
});

app.get("/", (req, res) => {
    res.status(200).type("text/plain").send(`Go to ${first}`);
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}.`);
});
```
{% endcode %}

## Solution

{% code overflow="wrap" %}
```py
from pwn import *
import requests
from bs4 import BeautifulSoup

context.log_level = 'debug'
url = 'https://crumbs.web.actf.co/'

response = requests.get(url)  # Initial request

# Loop until we see the flag (1000 times)
while 'actf' not in response.text:
    # Extract the next slug from <p>
    extracted = BeautifulSoup(response.text, features="lxml").p.contents[0][6:]
    debug('extracted: %s', extracted)
    # Visit the new page
    response = requests.get(url + extracted)

# Print the response if we got the flag
extracted = BeautifulSoup(response.text, features="lxml").p.contents[0]
warn(extracted)
```
{% endcode %}
