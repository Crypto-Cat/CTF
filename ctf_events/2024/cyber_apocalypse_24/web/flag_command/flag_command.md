---
name: Flag Command (2024)
event: HackTheBox Cyber Apocalypse CTF 2024
category: Web
description: Writeup for Flag Command (Web) - HackTheBox Cyber Apocalypse CTF (2024) 💜
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

# Flag Command

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/-vhl8ixthO4/0.jpg)](https://www.youtube.com/watch?v=-vhl8ixthO4?t=19 "HackTheBox Cyber Apocalypse '24: Flag Command (web)")

## Description

> Embark on the "Dimensional Escape Quest" where you wake up in a mysterious forest maze that's not quite of this world. Navigate singing squirrels, mischievous nymphs, and grumpy wizards in a whimsical labyrinth that may lead to otherworldly surprises. Will you conquer the enchanted maze or find yourself lost in a different dimension of magical challenges? The journey unfolds in this mystical escape!

## Solution

We load the webpage and find a terminal, enter a random string.

{% code overflow="wrap" %}
```bash
'hi' command not found. For a list of commands, type 'help'
```
{% endcode %}

OK, let's do it.

{% code overflow="wrap" %}
```bash
>> help

start Start the game
clear Clear the game screen
audio Toggle audio on/off
restart Restart the game
info Show info about the game
```
{% endcode %}

If we start the game, we can select one of 4 options. I choose to `HEAD NORTH`.

{% code overflow="wrap" %}
```bash
>> start

YOU WAKE UP IN A FOREST.

You have 4 options!
HEAD NORTH
HEAD SOUTH
HEAD EAST
HEAD WEST

>> HEAD NORTH

Venturing forth with the grace of a three-legged cat, you head North. Turns out, your sense of direction is as bad as your cooking - somehow, it actually works out this time. You stumble into a clearing, finding a small, cozy-looking tavern with "The Sloshed Squirrel" swinging on the signpost. Congratulations, you've avoided immediate death by boredom and possibly by beasties. For now...

You have 4 options!
GO DEEPER INTO THE FOREST
FOLLOW A MYSTERIOUS PATH
CLIMB A TREE
TURN BACK
```
{% endcode %}

We get another 4 options. At this point, let's check the web traffic in burp. There's a call to `/api/options` and in it are some possible commands. Notice we have a `secret` option.

{% code overflow="wrap" %}
```json
{
    "allPossibleCommands": {
        "1": ["HEAD NORTH", "HEAD WEST", "HEAD EAST", "HEAD SOUTH"],
        "2": [
            "GO DEEPER INTO THE FOREST",
            "FOLLOW A MYSTERIOUS PATH",
            "CLIMB A TREE",
            "TURN BACK"
        ],
        "3": [
            "EXPLORE A CAVE",
            "CROSS A RICKETY BRIDGE",
            "FOLLOW A GLOWING BUTTERFLY",
            "SET UP CAMP"
        ],
        "4": [
            "ENTER A MAGICAL PORTAL",
            "SWIM ACROSS A MYSTERIOUS LAKE",
            "FOLLOW A SINGING SQUIRREL",
            "BUILD A RAFT AND SAIL DOWNSTREAM"
        ],
        "secret": ["Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"]
    }
}
```
{% endcode %}

Let's send the secret message and receive the flag!

{% code overflow="wrap" %}
```bash
>> Blip-blop, in a pickle with a hiccup! Shmiggity-shmack

HTB{D3v3l0p3r_t00l5_4r3_b35t_wh4t_y0u_Th1nk??!}
```
{% endcode %}

Note: I didn't actually solve it like this. Instead I checked the JS before playing the game and saw this function.

{% code overflow="wrap" %}
```js
const fetchOptions = () => {
    fetch("/api/options")
        .then((data) => data.json())
        .then((res) => {
            availableOptions = res.allPossibleCommands;
        })
        .catch(() => {
            availableOptions = undefined;
        });
};
```
{% endcode %}

Subsequently, I made a GET request to this endpoint and discovered the secret option 😁

Flag: `HTB{D3v3l0p3r_t00l5_4r3_b35t_wh4t_y0u_Th1nk??!}`
