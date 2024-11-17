---
name: Layers (2024)
event: Intigriti 1337UP LIVE CTF 2024
category: Warmup
description: Writeup for Layers (Warmup) - 1337UP LIVE CTF (2024) 💜
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

# Layers

## Challenge Description

> Weird way to encode your data, but OK! 🤷‍♂️

## Solution

Players receive a ZIP archive to download, perhaps noticing the unusual order of extraction.

{% code overflow="wrap" %}
```bash
unzip layers.zip
Archive:  layers.zip
 extracting: 48
 extracting: 45
 extracting: 6
 extracting: 25
 extracting: 55
 extracting: 39
 extracting: 29
 extracting: 32
 extracting: 24
 extracting: 12
```
{% endcode %}

Each file contains a single byte of data.

{% code overflow="wrap" %}
```bash
cat 0
00110010
```
{% endcode %}

Maybe we can concatenate them and convert from binary?

{% code overflow="wrap" %}
```bash
cat *
0011001001001101011101010100111001010110010011100100010001111010011110100110000101100011011100110011100101100111011100110101011001001000010100110101010101001110010011100011100101100100010011100101011001001010010100110100111001100010011110100011001101100110011010100101010101010010011010100100111001000010010010010110101001010101011001000110101101010011011001100111100001111010001110010110010101000100011011110101001100110101010011100101001001010110
```
{% endcode %}

It translates to `2MuNVNDzzacs9gsVHSUNN9dNVJSNbz3fjURjNBIjUdkSfxz9eDoS5NRV`, which although plaintext, doesn't have a recognisable encoding (and fails with [magic](<https://gchq.github.io/CyberChef/#recipe=From_Binary('Space',8)Magic(3,false,false,'')&input=MDAxMTAwMTAwMTAwMTEwMTAxMTEwMTAxMDEwMDExMTAwMTAxMDExMDAxMDAxMTEwMDEwMDAxMDAwMTExMTAxMDAxMTExMDEwMDExMDAwMDEwMTEwMDAxMTAxMTEwMDExMDAxMTEwMDEwMTEwMDExMTAxMTEwMDExMDEwMTAxMTAwMTAwMTAwMDAxMDEwMDExMDEwMTAxMDEwMTAwMTExMDAxMDAxMTEwMDAxMTEwMDEwMTEwMDEwMDAxMDAxMTEwMDEwMTAxMTAwMTAwMTAxMDAxMDEwMDExMDEwMDExMTAwMTEwMDAxMDAxMTExMDEwMDAxMTAwMTEwMTEwMDExMDAxMTAxMDEwMDEwMTAxMDEwMTAxMDAxMDAxMTAxMDEwMDEwMDExMTAwMTAwMDAxMDAxMDAxMDAxMDExMDEwMTAwMTAxMDEwMTAxMTAwMTAwMDExMDEwMTEwMTAxMDAxMTAxMTAwMTEwMDExMTEwMDAwMTExMTAxMDAwMTExMDAxMDExMDAxMDEwMTAwMDEwMDAxMTAxMTExMDEwMTAwMTEwMDExMDEwMTAxMDAxMTEwMDEwMTAwMTAwMTAxMDExMA&oeol=VT>)).

Notice that if we check the timestamps of the files, they weren't created in the order you would expect (sequentially, according to their filenames).

{% code overflow="wrap" %}
```bash
ls -lart
total 224
-rw-r--r-- 1 crystal crystal   8 Aug 19 17:09 48
-rw-r--r-- 1 crystal crystal   8 Aug 19 17:10 45
-rw-r--r-- 1 crystal crystal   8 Aug 19 17:10 6
-rw-r--r-- 1 crystal crystal   8 Aug 19 17:11 25
-rw-r--r-- 1 crystal crystal   8 Aug 19 17:11 55
-rw-r--r-- 1 crystal crystal   8 Aug 19 17:12 39
-rw-r--r-- 1 crystal crystal   8 Aug 19 17:12 29
-rw-r--r-- 1 crystal crystal   8 Aug 19 17:13 32
-rw-r--r-- 1 crystal crystal   8 Aug 19 17:13 24
-rw-r--r-- 1 crystal crystal   8 Aug 19 17:14 12
-rw-r--r-- 1 crystal crystal   8 Aug 19 17:14 8
-rw-r--r-- 1 crystal crystal   8 Aug 19 17:15 31
-rw-r--r-- 1 crystal crystal   8 Aug 19 17:15 52
```
{% endcode %}

Let's try to concatenate in ascending order by timestamp, instead of filename. We can use a script to automate the whole process.

{% code overflow="wrap" %}
```python
import zipfile
import os
from datetime import datetime

ARCHIVE_NAME = "layers.zip"
EXTRACT_DIR = "files"

def binary_to_char(binary_str):
    return chr(int(binary_str, 2))

with zipfile.ZipFile(ARCHIVE_NAME, 'r') as zipf:
    for info in zipf.infolist():
        extracted_path = zipf.extract(info, EXTRACT_DIR)
        date_time = datetime(*info.date_time)
        mod_time = date_time.timestamp()
        os.utime(extracted_path, (mod_time, mod_time))

file_data = []
for file_name in os.listdir(EXTRACT_DIR):
    file_path = os.path.join(EXTRACT_DIR, file_name)
    mod_time = os.path.getmtime(file_path)
    with open(file_path, "r") as f:
        binary_data = f.read().strip()
        char = binary_to_char(binary_data)
    file_data.append((mod_time, char))

file_data.sort()
reconstructed_string = ''.join([char for _, char in file_data])

print("Reconstructed String:")
print(reconstructed_string)

for file_name in os.listdir(EXTRACT_DIR):
    os.remove(os.path.join(EXTRACT_DIR, file_name))
os.rmdir(EXTRACT_DIR)
```
{% endcode %}

{% code overflow="wrap" %}
```bash
python solve.py
Reconstructed String:
SU5USUdSSVRJezdoM3IzNV9sNHkzcjVfNzBfN2gxNV9jaDRsbDNuNjN9
```
{% endcode %}

What happens if we run [magic on this one?](<https://gchq.github.io/CyberChef/#recipe=Magic(3,false,false,'')&input=U1U1VVNVZFNTVlJKZXpkb00zSXpOVjlzTkhremNqVmZOekJmTjJneE5WOWphRFJzYkROdU5qTjk&oeol=VT>)

It's detected as [Base64 encoding](<https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=U1U1VVNVZFNTVlJKZXpkb00zSXpOVjlzTkhremNqVmZOekJmTjJneE5WOWphRFJzYkROdU5qTjk&oeol=VT>) 😎

Flag: `INTIGRITI{7h3r35_l4y3r5_70_7h15_ch4ll3n63}`
