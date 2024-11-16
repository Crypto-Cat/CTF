---
name: Password Management (2024)
event: Intigriti 1337UP LIVE CTF 2024
category: Forensics
description: Writeup for Password Management (Forensics) - 1337UP LIVE CTF (2024) 💜
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

# Password Management

## Challenge Description

> My computer broke and I don't know what to do! Can you take a look at the drive? There shouldn't be any sensitive information on there, I deleted personal files a while ago..

## Solution

-   Players will download the disk image and analyse it with some forensics tool, e.g. `FTKImager` or `Autopsy`
-   They will find 13 images that were deleted (and recycle bin emptied), but this doesn't erase them fully!
-   12 of the images are AI generated, the last 1 is a photograph of a password: `SevenSuns397260`
-   Players can find reference of interesting website visit `super-really-real-bank.com`.
-   Next, players should extract the Firefox browser data
-   When they try to access the profile (saved passwords, browser history, cookies etc) there is a master password
-   Players use the password they found earlier to unlock the data, then in the cookies/saved passwords will be the flag

Flag: `INTIGRITI{4n_unf0r7un473_53r135_0f_m1574k35}`
