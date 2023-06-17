---
CTF: Nahamcon 2023
Challenge Name: Hidden Figures
Category: Web
Date: 15/06/23
Author: JohnHammond
Points: 398
Solves: 145
---
[![Nahamcon CTF 2023: Hidden Figures (Web)](https://img.youtube.com/vi/XHg_sBD0-es/0.jpg)](https://www.youtube.com/watch?v=XHg_sBD0-es?t=705 "Nahamcon CTF 2023: Hidden Figures (Web)")

### Description
>Look at this fan page I made for the Hidden Figures movie and website! Not everything is what it seems! 

## Recon
`/assets` directory is accessible.

Had a look through the files, JS (and CSS based on challenge name) but didn't see anything interesting.

Downloaded main image and checked exifdata, strings, embedded files etc.

## Solution
Teammate noticed base64 encoded data in the `<img data-src>` tag on line 298 when you view the page source.

Save to file and decode.
```bash
base64 -d data.b64 > output
```

File type is image.
```bash
file output

file: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 1600x2409, components 3
```

```bash
mv file test.jpg
```

Diff with the original image we downloaded during recon.
```bash
diff test.jpg Hidden+Figures+Paperback+Movie+Tie+In+Cover.jpeg 
Binary files test.jpg and Hidden+Figures+Paperback+Movie+Tie+In+Cover.jpeg differ
```

The base64 one is bigger!
```
foremost test.jpg
```

We get two images out, one is the movie poster, the other a mario image containing a quote.
```txt
THANK YOU MARIO!

BUT OUR PRINCESS IS IN ANOTHER CASTLE!
```

Check the other images, until we get the flag in a PNG file.

Let's make life easy for ourselves and [convert image to text](https://www.howtogeek.com/devops/how-to-convert-images-to-text-on-the-linux-command-line-with-ocr)
```bash
sudo apt install tesseract-ocr libtesseract-dev tesseract-ocr-eng

tesseract -l eng 00000030.png output

cat output.txt
```

Now we have a flag to copy and paste!
```txt
flag{e62630124508ddb3952843F183843343}
```