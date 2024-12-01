---
name: No Comment (2024)
event: Intigriti 1337UP LIVE CTF 2024
category: OSINT
description: Writeup for No Comment (OSINT) - 1337UP LIVE CTF (2024) 💜
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

# No Comment

## Video walkthrough

[![VIDEO](https://img.youtube.com/vi/uzwKwI72FDQ/0.jpg)](https://youtu.be/uzwKwI72FDQ "OSINT: Following the Breadcrumbs")

## Challenge Description

> Or is there? 🤔

## Solution

Players download this cool image 😎

![](./images/0.jpg)

Could check for embedded files or stego, or perhaps do a reverse image lookup on Google or TinEye.

In fact, the title and description is a hint! If we check the image metadata (EXIF), we'll see a comment.

{% code overflow="wrap" %}

```bash
exiftool ripple.jpg
ExifTool Version Number         : 12.57
File Name                       : ripple.jpg
Directory                       : .
File Size                       : 6.5 MB
File Modification Date/Time     : 2024:09:21 15:51:46+01:00
File Access Date/Time           : 2024:11:10 11:24:06+00:00
File Inode Change Date/Time     : 2024:11:12 11:10:15+00:00
File Permissions                : -rwxrw-rw-
File Type                       : JPEG
File Type Extension             : jpg
MIME Type                       : image/jpeg
Comment                         : /a/pq6TgwS
Image Width                     : 4032
Image Height                    : 3024
Encoding Process                : Baseline DCT, Huffman coding
Bits Per Sample                 : 8
Color Components                : 3
Y Cb Cr Sub Sampling            : YCbCr4:2:0 (2 2)
Image Size                      : 4032x3024
Megapixels                      : 12.2
```

{% endcode %}

Recognise the comment format? It's from Imgur, where [URLs are formatted](https://www.reddit.com/r/redditdev/comments/35bb7i/imgur_link_format) like `imgur.com/a/{alphanumeric}` (albums) and `imgur.com/g/{alphanumeric}` (galleries).

Let's visit the [imgur link](imgur.com/a/pq6TgwS) and see the same image, along with a comment.

{% code overflow="wrap" %}

```
V2hhdCBhICJsb25nX3N0cmFuZ2VfdHJpcCIgaXQncyBiZWVuIQoKaHR0cHM6Ly9wYXN0ZWJpbi5jb20vRmRjTFRxWWc=
```

{% endcode %}

We [base64 decode it..](<https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=VjJoaGRDQmhJQ0pzYjI1blgzTjBjbUZ1WjJWZmRISnBjQ0lnYVhRbmN5QmlaV1Z1SVFvS2FIUjBjSE02THk5d1lYTjBaV0pwYmk1amIyMHZSbVJqVEZSeFdXYz0>)

{% code overflow="wrap" %}

```
What a "long_strange_trip" it's been!

https://pastebin.com/FdcLTqYg
```

{% endcode %}

Visit the [pastebin link](https://pastebin.com/FdcLTqYg) and find a password protected note. Enter `long_strange_trip` to uncover a hex string.

Converting from hex [doesn't work](<https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')&input=MjUyMTNhMmUxODIxM2QyNjI4MTUwZTBiMmMwMDEzMGUwMjBkMDI0MDA0MzAxZTViMDAwNDBiMGI0YTFjNDMwYTMwMjMwNDA1MjMwNDA5NDMwOQ&oeol=VT>), so we check the users public pastes and find [this one..](https://pastebin.com/UavLs18i)

{% code overflow="wrap" %}

```
I've been learning all about cryptography recently, it's cool you can just XOR data with a password and nobody can recover it!!

I think I've learnt enough about that now, hopefully I'll learn something new in next weeks topic: https://specopssoft.com/blog/password-reuse-hidden-danger
```

{% endcode %}

Quite a hint, but at the last minute I worried this part was too guessy. We XOR the data with the same password and [get the flag](<https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Latin1','string':'long_strange_trip'%7D,'Standard',false)&input=MjUyMTNhMmUxODIxM2QyNjI4MTUwZTBiMmMwMDEzMGUwMjBkMDI0MDA0MzAxZTViMDAwNDBiMGI0YTFjNDMwYTMwMjMwNDA1MjMwNDA5NDMwOQ&oeol=VT>) 🙂

Flag: `INTIGRITI{instagram.com/reel/C7xYShjMcV0}`

Fun fact: the insta reel is from a concert I saw in the Las Vegas sphere and I will never stop talking about it 😂
