---
name: Hidden Figures (2023)
event: Nahamcon CTF 2023
category: Web
description: Writeup for Hidden Figures (Web) - Nahamcon CTF (2023) 💜
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

# Hidden Figures

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/XHg_sBD0-es/0.jpg)](https://www.youtube.com/watch?v=XHg_sBD0-es?t=705 "Nahamcon CTF 2023: Hidden Figures (Web)")

## Description

> Look at this fan page I made for the Hidden Figures movie and website! Not everything is what it seems!

## Recon

`/assets` directory is accessible.

Had a look through the files, JS (and CSS based on challenge name) but didn't see anything interesting.

Downloaded main image and checked exifdata, strings, embedded files etc.

## Solution

Teammate noticed base64 encoded data in the `<img data-src>` tag on line 298 when you view the page source.

Save to file and decode.

{% code overflow="wrap" %}
```bash
base64 -d data.b64 > output
```
{% endcode %}

File type is image.

{% code overflow="wrap" %}
```bash
file output

file: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 1600x2409, components 3
```
{% endcode %}

{% code overflow="wrap" %}
```bash
mv file test.jpg
```
{% endcode %}

Diff with the original image we downloaded during recon.

{% code overflow="wrap" %}
```bash
diff test.jpg Hidden+Figures+Paperback+Movie+Tie+In+Cover.jpeg
Binary files test.jpg and Hidden+Figures+Paperback+Movie+Tie+In+Cover.jpeg differ
```
{% endcode %}

The base64 one is bigger!

{% code overflow="wrap" %}
```
foremost test.jpg
```
{% endcode %}

We get two images out, one is the movie poster, the other a mario image containing a quote.

{% code overflow="wrap" %}
```txt
THANK YOU MARIO!

BUT OUR PRINCESS IS IN ANOTHER CASTLE!
```
{% endcode %}

Check the other images, until we get the flag in a PNG file.

Let's make life easy for ourselves and [convert image to text](https://www.howtogeek.com/devops/how-to-convert-images-to-text-on-the-linux-command-line-with-ocr)

{% code overflow="wrap" %}
```bash
sudo apt install tesseract-ocr libtesseract-dev tesseract-ocr-eng

tesseract -l eng 00000030.png output

cat output.txt
```
{% endcode %}

Now we have a flag to copy and paste!

Flag: `flag{e62630124508ddb3952843F183843343}`
