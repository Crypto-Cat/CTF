---
name: Triage Bot v2 (2024)
event: Intigriti 1337UP LIVE CTF 2024
category: Misc
description: Writeup for Triage Bot v2 (Misc) - 1337UP LIVE CTF (2024) 💜
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

# Triage Bot v2

## Challenge Description

> Check out our new and improved Triage Bot!

The 2023 1337UP LIVE CTF featured a `TriageBot` challenge that used an LLM (ChatGPT) to triage reports. Players had to force the bot to leak it's initial prompt (against it's instructions). If you missed it, check out the [video walkthrough](https://www.youtube.com/watch?v=5wcJjNgncOQ).

## Solution

This years challenge is a lot easier than last years, partially because common feedback in both of the previous CTFs was "not enough beginner challenges". Another reason for the simplicity of this challenge solution is we were concerned about the [security of our discord server](https://hanasuru.medium.com/how-we-found-unintended-bypass-to-exploiting-entire-cyberthreatforce-discord-server-d93951b9efab) and opted to play it safe 😂

Here's the help menu for the discord bot.

![](./images/0.PNG)

According to the `!news` command, there's a new `!read_report` command.

![](./images/1.PNG)

However, we lack the permissions to use it 🤔

![](./images/2.PNG)

Let's try the rest of the commands.

![](./images/3.PNG)

![](./images/4.PNG)

![](./images/5.PNG)

Not much functionality, apart from the cool AI generated images 😎

We need the `triage` role! We won't be able to give ourselves that role in the intigriti discord server. So we need to invite the bot to our own server, where we can assign ourselves the role.

![](./images/6.PNG)

Now, we can read reports.

![](./images/7.PNG)

It appears to give a random one each time. What if we specify an ID?

![](./images/8.PNG)

Interesting! How about ID `0`?

![](./images/9.PNG)

We have the flag!

Flag: `INTIGRITI{4n07h3r_y34r_4n07h3r_7r1463_b07}`
