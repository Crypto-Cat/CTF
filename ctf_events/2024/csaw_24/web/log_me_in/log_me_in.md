---
name: Log Me In (2024)
event: CSAW CTF 2024
category: Web
description: Writeup for Log Me In (Web) - CSAW CTF (2024) 💜
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

# Log Me In

## Description

> I (definitely did not) have found this challenge in the OSIRIS recruit repository

## Source Code

{% code overflow="wrap" %}

```python
from flask import make_response, session, Blueprint, request, jsonify, render_template, redirect, send_from_directory
from pathlib import Path
from hashlib import sha256
from utils import is_alphanumeric
from models import Account, db
from utils import decode, encode

flag = (Path(__file__).parent / "flag.txt").read_text()

pagebp = Blueprint('pagebp', __name__)

@pagebp.route('/')
def index():
    return send_from_directory("static", 'index.html')

@pagebp.route('/login', methods=["GET", "POST"])
def login():
    if request.method != 'POST':
        return send_from_directory('static', 'login.html')
    username = request.form.get('username')
    password = sha256(request.form.get('password').strip().encode()).hexdigest()
    if not username or not password:
        return "Missing Login Field", 400
    if not is_alphanumeric(username) or len(username) > 50:
        return "Username not Alphanumeric or longer than 50 chars", 403
    # check if the username already exists in the DB
    user = Account.query.filter_by(username=username).first()
    if not user or user.password != password:
        return "Login failed!", 403
    user = {
        'username':user.username,
        'displays':user.displayname,
        'uid':user.uid
    }
    token = encode(dict(user))
    if token == None:
        return "Error while logging in!", 500
    response = make_response(jsonify({'message': 'Login successful'}))
    response.set_cookie('info', token, max_age=3600, httponly=True)
    return response

@pagebp.route('/register', methods=['GET', 'POST'])
def register():
    if request.method != 'POST':
        return send_from_directory('static', 'register.html')
    username = request.form.get('username')
    password = sha256(request.form.get('password').strip().encode()).hexdigest()
    displayname = request.form.get('displayname')
    if not username or not password or not displayname:
        return "Missing Registration Field", 400
    if not is_alphanumeric(username) or len(username) > 50:
        return "Username not Alphanumeric or it is longer than 50 chars", 403
    if not is_alphanumeric(displayname) or len(displayname) > 50:
        return "Displayname not Alphanumeric or it is longer than 50 chars", 403
    # check if the username already exists in the DB
    user = Account.query.filter_by(username=username).first()
    if user:
        return "Username already taken!", 403
    acc = Account(
        username=username,
        password=password,
        displayname=displayname,
        uid=1
        )
    try:
        # Add the new account to the session and commit it
        db.session.add(acc)
        db.session.commit()
        return jsonify({'message': 'Account created successfully'}), 201
    except Exception as e:
        db.session.rollback()  # Roll back the session on error
        return jsonify({'error': str(e)}), 500

@pagebp.route('/user')
def user():
    cookie = request.cookies.get('info', None)
    name='hello'
    msg='world'
    if cookie == None:
        return render_template("user.html", display_name='Not Logged in!', special_message='Nah')
    userinfo = decode(cookie)
    if userinfo == None:
        return render_template("user.html", display_name='Error...', special_message='Nah')
    name = userinfo['displays']
    msg = flag if userinfo['uid'] == 0 else "No special message at this time..."
    return render_template("user.html", display_name=name, special_message=msg)

@pagebp.route('/logout')
def logout():
    session.clear()
    response = make_response(redirect('/'))
    response.set_cookie('info', '', expires=0)
    return response
```

{% endcode %}

## Solution

To get the flag, we need to visit the `/user` endpoint with our UID set to zero.

{% code overflow="wrap" %}

```python
msg = flag if userinfo['uid'] == 0 else "No special message at this time..."
```

{% endcode %}

We can register an account and log in; notice how the UID is set?

{% code overflow="wrap" %}

```python
user = {
	'username':user.username,
	'displays':user.displayname,
	'uid':user.uid
}
token = encode(dict(user))
```

{% endcode %}

It uses a custom `encode` function, imported from `utils.py`

{% code overflow="wrap" %}

```python
def is_alphanumeric(text):
    pattern = r'^[a-zA-Z0-9]+$'
    if re.match(pattern, text):
        return True
    else:
        return False

def LOG(*args, **kwargs):
    print(*args, **kwargs, flush=True)

# Some cryptographic utilities
def encode(status: dict) -> str:
    try:
        plaintext = json.dumps(status).encode()
        out = b''
        for i,j in zip(plaintext, os.environ['ENCRYPT_KEY'].encode()):
            out += bytes([i^j])
        return bytes.hex(out)
    except Exception as s:
        LOG(s)
        return None

def decode(inp: str) -> dict:
    try:
        token = bytes.fromhex(inp)
        out = ''
        for i,j in zip(token, os.environ['ENCRYPT_KEY'].encode()):
            out += chr(i ^ j)
        user = json.loads(out)
        return user
    except Exception as s:
        LOG(s)
        return None
```

{% endcode %}

The JSON object is XORd with the key. Sounds like an OTP issue? If we encode two different user objects (`c1` and `c2`) and then XOR them together, we should recover the key!

My first attempt at this failed; the username/display name probably needed to be longer (hinted at by the 50-char length limits). The problem was finding 50 char names that hadn't already been taken lol.

{% code overflow="wrap" %}

```
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABB = 48674c3731025651282f614a4d5437132579332603202236367628351513723226782c30060a3939302a351b0e313339000f0b28190738107417743b0209702d535e551417281f1c2114361540494e6b36767573360e340e02122a25181b251370220a05280c0d0a083923112904280f3b247604247231760a25071523360c733330114a55604c0f02724d6e7027

BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBAA = 48674c3731025651282f614a4d543410267a30250023213535752b3616107131257b2f3305093a3a332936180d32303a030c082b1a043b1377147738010a732e535e551417281f1c2114361540494e6b35757670350d370d011129261b182610732109062b0f0e090b3a20122a072b0c38277507277132750926041620350f703033114a55604c0f02724d6e7027
```

{% endcode %}

I used CyberChef to [recover the key](<https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto'/disabled)XOR(%7B'option':'Hex','string':'48674c3731025651282f614a4d5437132579332603202236367628351513723226782c30060a3939302a351b0e313339000f0b28190738107417743b0209702d535e551417281f1c2114361540494e6b36767573360e340e02122a25181b251370220a05280c0d0a083923112904280f3b247604247231760a25071523360c733330114a55604c0f02724d6e7027'%7D,'Standard',false)&input=eyJ1c2VybmFtZSI6ICJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFCQiIsICJkaXNwbGF5cyI6ICJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFCQiIsICJ1aWQiOiAwfQ&oeol=FF>):

{% code overflow="wrap" %}

```
3E9DTp80EJCpmvvRd8rgBacww7itTR3sg9mqGKxxqktZOprxANJiXFyQ5V5zCH2oqru6sAllMuOfbsnIw742wOuOCSkdYZdR1cKDiMLKIxbPhEiNze7Ee3p7KdFTbwM2qr3fuB9ffPwN@Z
```

{% endcode %}

Last step is to [generate a new (signed) cookie with the UID set to zero](<https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto'/disabled)XOR(%7B'option':'Latin1','string':'3E9DTp80EJCpmvvRd8rgBacww7itTR3sg9mqGKxxqktZOprxANJiXFyQ5V5zCH2oqru6sAllMuOfbsnIw742wOuOCSkdYZdR1cKDiMLKIxbPhEiNze7Ee3p7KdFTbwM2qr3fuB9ffPwN@Z'%7D,'Standard',false)To_Hex('None',0)&input=eyJ1c2VybmFtZSI6IkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUJCIiwiZGlzcGxheXMiOiJBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFCQiIsInVpZCI6MH0&oeol=FF>):

{% code overflow="wrap" %}

```
48674c3731025651282f614a4f3737132579332603202236367628351513723226782c30060a3939302a351b0e313339000f0b28190738107417743b020a704d5d50115f0031000d34066d5c40322f0836767573360e340e02122a25181b251370220a05280c0d0a083923112904280f3b247604247231760a25071523350f105d50460f116003561b
```

{% endcode %}

Update the cookie in the browser, then visit the `/user` endpoint and you will receive the flag!

Flag: `csawctf{S3NS1T1V3_D4T4_ST0R3D_CL13NTS1D3D_B4D_B4D}`
