---
name: Perfect Picture (2023)
event: Imaginary 2023
category: Web
description: Writeup for Perfect Picture (Web) - Imaginary (2023) 💜
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

# Perfect Picture

## Description

> Someone seems awful particular about where their pixels go...

Source code is provided, so let's review it before we check [the site](http://perfect-picture.chal.imaginaryctf.org).

## Recon

There's 75 LOC in `app.py` so let's breakdown the important parts.

The storage location of uploaded images and allowed extensions are configured.

{% code overflow="wrap" %}
```python
app.config['UPLOAD_FOLDER'] = '/dev/shm/uploads/'
app.config['ALLOWED_EXTENSIONS'] = {'png'}
```
{% endcode %}

When we upload a file, it splits on a `.` and looks at the rightmost split (extension). If the lowercase string matches the allowed extension (`png`) then the filename is allowed.

{% code overflow="wrap" %}
```python
return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']
```
{% endcode %}

Next, a random image name is generated.

{% code overflow="wrap" %}
```python
img_name = f'{str(random.randint(10000, 99999))}.png'
```
{% endcode %}

A `check` function is called which will first read the flag into a variable.

{% code overflow="wrap" %}
```python
with open('flag.txt', 'r') as f:
	flag = f.read()
```
{% endcode %}

The dimensions of the image must be `690 x 420 (w x h)` and specific pixels need match the expected colours.

{% code overflow="wrap" %}
```python
with Image.open(app.config['UPLOAD_FOLDER'] + uploaded_image) as image:
	w, h = image.size
	if w != 690 or h != 420:
		return 0
	if image.getpixel((412, 309)) != (52, 146, 235, 123):
		return 0
	if image.getpixel((12, 209)) != (42, 16, 125, 231):
		return 0
	if image.getpixel((264, 143)) != (122, 136, 25, 213):
		return 0
```
{% endcode %}

Next, `exiftool` confirms that the metadata is as expected.

{% code overflow="wrap" %}
```python
if metadata["PNG:Description"] != "jctf{not_the_flag}":
	return 0
if metadata["PNG:Title"] != "kool_pic":
	return 0
if metadata["PNG:Author"] != "anon":
	return 0
```
{% endcode %}

If all the checks pass, the flag will be returned!

## Solution

OK, so based on our analysis we need to create an image with the following properties:

-   Dimension (w x h) of `690 x 420`
-   Pixel (`412, 309`) is (`52, 146, 235, 123`)
-   Pixel (`12, 209`) is (`42, 16, 125, 231`)
-   Pixel (`264, 143`) is (`122, 136, 25, 213`)
-   Image `description` is `jctf{not_the_flag}`
-   Image `title` is `kool_pic`
-   Image `author` is `anon`

I'm lazy, so asked ChatGPT to make a python script (note: exif packages failed for me, as they were strict on keys so used subprocess with exiftool instead).

{% code overflow="wrap" %}
```python
from PIL import Image, ImageDraw
import subprocess

# Define the image dimensions
width = 690
height = 420

# Create a blank image with a white background
image = Image.new("RGBA", (width, height), (255, 255, 255, 255))
draw = ImageDraw.Draw(image)

# Set the specified pixel values
pixels = {
    (412, 309): (52, 146, 235, 123),
    (12, 209): (42, 16, 125, 231),
    (264, 143): (122, 136, 25, 213)
}

for (x, y), color in pixels.items():
    draw.point((x, y), fill=color)

# Save the image without metadata
image.save("generated_image.png")

# Close the image
image.close()

# Add image description, title, and author as metadata using exiftool
description = "jctf{not_the_flag}"
title = "kool_pic"
author = "anon"

subprocess.run([
    "exiftool",
    "-Description=" + description,
    "-Author=" + author,
    "-Title=" + title,
    "generated_image.png"
])
```
{% endcode %}

We upload the generated image and receive the flag in return.

Flag: `ictf{7ruly_th3_n3x7_p1c4ss0_753433}`
