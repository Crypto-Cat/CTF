---
name: Bug Squash (part 1) (2024)
event: Intigriti 1337UP LIVE CTF 2024
category: Gamepwn
description: Writeup for Bug Squash (part 1) (Gamepwn) - 1337UP LIVE CTF (2024) 💜
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

# Bug Squash (part 1)

## Video walkthrough

[![VIDEO](https://img.youtube.com/vi/VoT74JOGWgA/0.jpg)](https://youtu.be/VoT74JOGWgA "Hacking Unity Games with Cheat Engine and dnSpy")

## Challenge Description

> Squash those bugs!

I'll improve the writeup! check the video walkthrough too 😊

## Solution

-   Goal is to set score to `-1337`
-   Can do so by modifying score in memory with a tool like `cheat engine`
-   Alternatively, patch the C# code with a tool like `dnSpy`
-   Could also solve by reversing the crypto + extracting keys and manually decrypt flag image but it's more work than necessary

Flag: `INTIGRITI{game_hacking_is_fun!}`
