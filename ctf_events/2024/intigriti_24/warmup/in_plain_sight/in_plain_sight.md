---
name: In Plain Sight (2024)
event: Intigriti 1337UP LIVE CTF 2024
category: Warmup
description: Writeup for In Plain Sight (Warmup) - 1337UP LIVE CTF (2024) 💜
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

# In Plain Sight

## Challenge Description

> Barely hidden tbh..

## Solution

Players download an image of a cute cat (his name is Yang 💜).

![](./images/0.jpg)

Running a tool like `foremost` or `binwalk` will reveal an embedded file.

{% code overflow="wrap" %}

```bash
binwalk -e meow.jpg

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
2144878       0x20BA6E        Zip archive data, encrypted at least v2.0 to extract, compressed size: 1938, uncompressed size: 3446, name: flag.png
2146976       0x20C2A0        End of Zip archive, footer length: 22
```

{% endcode %}

If we try to unzip the archive, we'll see it's encrypted.

{% code overflow="wrap" %}

```bash
unzip 20BA6E.zip
Archive:  20BA6E.zip
[20BA6E.zip] flag.png password:
```

{% endcode %}

Returning to the original JPG, check the strings.

{% code overflow="wrap" %}

```bash
strings -n 10 meow.jpg

)D8^FricdRr
Y'~>vfc]*.
YoullNeverGetThis719482
flag.pngUT
```

{% endcode %}

Try `YoullNeverGetThis719482` as a password.

{% code overflow="wrap" %}

```bash
unzip 20BA6E.zip
Archive:  20BA6E.zip
[20BA6E.zip] flag.png password:
replace flag.png? [y]es, [n]o, [A]ll, [N]one, [r]ename: y
  inflating: flag.png
```

{% endcode %}

Opening the image, it appears to be pure white.

![](./images/1.png)

However, if we open with MS paint (or alternative) and use the paint bucket (fill) tool, the flag will be revealed.

![](./images/2.png)

Flag: `INTIGRITI{w4rmup_fl46z}`
