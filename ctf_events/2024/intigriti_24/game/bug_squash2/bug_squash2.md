---
name: Bug Squash (part 2) (2024)
event: Intigriti 1337UP LIVE CTF 2024
category: Gamepwn
description: Writeup for Bug Squash (part 2) (Gamepwn) - 1337UP LIVE CTF (2024) 💜
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

# Bug Squash (part 2)

## Video walkthrough

[![VIDEO](https://img.youtube.com/vi/dEA68Aa0V-s/0.jpg)](https://youtu.be/dEA68Aa0V-s "Bypassing Server-side Anti-Cheat Protections")

## Challenge Description

> The developers learned some important things about cheaters and now hope they've learnt their lesson. Rumour has it, if you score more than 100,000 points in this game (within the 2 min time limit), you'll get a flag. Watch out for that new anti-cheat system though!

## Solution

The description indicates we need more than 100,000 points to win, but there's a 2 minute time limit on each game 🤔

![](./images/0.PNG)

We'll struggle to decompile the game as we did in part 1 due to it being compiled with `IL2CPP` instead of `Mono`. You could still attach cheat engine and reverse the code as DavidP did in [this video](https://youtu.be/Nk-TNzHxN0M) (he actually reconstructed the C# code from assembly!)

My expected approach was to open Wireshark and see some network traffic when the game is running. Since the traffic is HTTPS, players have to do a little work to decrypt it.

-   Setup Windows proxy `127.0.0.1:8080`
-   Setup burp cert to capture HTTPS traffic
    -   Export proxy cert in PKCS format
    -   `Windows > Manage user certificates > Trusted Root Certification Authorities > Certificates > All Tasks > Import`
    -   Traffic will now show in burp

The `/start_game` endpoint will initialise a game.

![](./images/1.PNG)

Each time we score a point, a request is issued to the `/update_score` endpoint.

![](./images/2.PNG)

We can try to modify the traffic to change the points but from trial and error we will find some conditions

-   Anti-cheat resets users score if they send more then 3 request per second
-   Anti-cheat rejects any point values that aren't 1 (and resets score)
-   Anti-cheat checks that players score didn't jump to an unrealistic number (more than 4096 per request)

![](./images/3.PNG)

The game resets every 2 mins so by the anti-cheat rules, max attainable score is `(120 * 3)`)

Since they can't change the value, I thought players might play around with the keys.

```json
`{"5e258b4a-23cf-469c-9264-b73856d9fe20": "insert_id", "bugs_squashed": 1, "bugs_squashed": 1}`
```

This would fail because the keys are duplicate. The thing about JSON is the [keys are non case-sensitive](https://www.quora.com/Is-JSON-case-sensitive), so I hoped players would try to send `BUGS_SQUASHED` as well as`bugs_squashed` and see they score points.

So yes, intended solution is to send `{"user_id": "insert_id", "bugs_squashed": 1, "bUgs_squashed": 1, "buGs_squashed": 1}` etc, where you can send 4096 variations per request at a max speed of 3 requests per second. Here's a solve script to do that.

### solve.py

{% code overflow="wrap" %}

```python
import requests
import itertools
import time

BASE_URL = 'https://bugsquash.ctf.intigriti.io'

def generate_variations(s):
    """Generate all case variations of a string."""
    return [''.join(variant) for variant in itertools.product(*([letter.lower(), letter.upper()] for letter in s))]

def start_game(session):
    """Start a new game session and return the user_id."""
    response = session.post(f'{BASE_URL}/start_game')
    response_data = response.json()
    user_id = response_data['user_id']
    score = response_data['score']
    print(f"Game started! User ID: {user_id}, Initial Score: {score}")
    return user_id, score

def update_score(session, user_id, variations):
    """Send score updates to the server using all variations of 'bugs_squashed'."""
    json_data = {"user_id": user_id}
    json_data.update({variation: 1 for variation in variations})

    response = session.post(
        f'{BASE_URL}/update_score', json=json_data)
    response_data = response.json()

    if "error" in response_data:
        print(f"Error: {response_data['error']}")
    elif "message" in response_data:
        print(
            f"Message: {response_data['message']}, Current Score: {response_data['score']}")

    return response_data.get('score', 0)

def play_game(variations, target_score=100000):
    """Play the game until the target score is reached."""
    with requests.Session() as session:
        user_id, score = start_game(session)

        print(len(variations))

        while score < target_score:
            score = update_score(session, user_id, variations)
            time.sleep(0.333)  # 3 requests per second

        print(f"Target score reached! Final Score: {score}")

if __name__ == "__main__":
    variations = generate_variations("bugs_squashed")
    play_game(variations)
```

{% endcode %}

Run the solve script.

```bash
python solve.py
Game started! User ID: 700d9b33-1eef-42d0-bf37-afcc41a857cf, Initial Score: 0
8192
Message: Score updated by 4096 points., Current Score: 4096
Message: Score updated by 4096 points., Current Score: 8192
Message: Score updated by 4096 points., Current Score: 12288
Message: Score updated by 4096 points., Current Score: 16384
Message: Score updated by 4096 points., Current Score: 20480
Message: Score updated by 4096 points., Current Score: 24576
Message: Score updated by 4096 points., Current Score: 28672
Message: Score updated by 4096 points., Current Score: 32768
Message: Score updated by 4096 points., Current Score: 36864
Message: Score updated by 4096 points., Current Score: 40960
Message: Score updated by 4096 points., Current Score: 45056
Message: Score updated by 4096 points., Current Score: 49152
Message: Score updated by 4096 points., Current Score: 53248
Message: Score updated by 4096 points., Current Score: 57344
Message: Score updated by 4096 points., Current Score: 61440
Message: Score updated by 4096 points., Current Score: 65536
Message: Score updated by 4096 points., Current Score: 69632
Message: Score updated by 4096 points., Current Score: 73728
Message: Score updated by 4096 points., Current Score: 77824
Message: Score updated by 4096 points., Current Score: 81920
Message: Score updated by 4096 points., Current Score: 86016
Message: Score updated by 4096 points., Current Score: 90112
Message: Score updated by 4096 points., Current Score: 94208
Message: Score updated by 4096 points., Current Score: 98304
Message: INTIGRITI{64m3_h4ck1n6_4n71ch347_15_4l50_fun!}, Current Score: 102400
Target score reached! Final Score: 102400
```

Flag: `INTIGRITI{64m3_h4ck1n6_4n71ch347_15_4l50_fun!}`

This challenge didn't get a lot of solves and people found it guessy. Thinking back on it, it was! I wish I did something different 😞 Here's the server-side code for those interested.

### server.py

{% code overflow="wrap" %}

```python
from flask import Flask, request, jsonify
import uuid
import os
import logging
import time
from redis import Redis

flag = os.getenv('FLAG', 'INTIGRITI{fake_flag}')

app = Flask(__name__)

# Set up logging
logging.basicConfig(level=logging.INFO)

# Configure Redis connection using environment variables
redis_host = os.getenv('HOST', 'localhost')
redis_port = os.getenv('PORT', '6379')
redis_user = os.getenv('USERNAME', '')
redis_pass = os.getenv('PASSWORD', '')

# Construct Redis URL (e.g., redis://username:password@hostname:port/0)
redis_url = f"rediss://{redis_user}:{redis_pass}@{redis_host}:{redis_port}" if redis_user and redis_pass else f"redis://{redis_host}:{redis_port}"
# Connect to Redis
redis_client = Redis.from_url(redis_url)

# Session duration and rate limit settings
SESSION_DURATION = 120  # 2 minutes
RATE_LIMIT = 3  # requests
RATE_LIMIT_WINDOW = 1  # second

@app.route('/start_game', methods=['POST'])
def start_game():
    """Initialize a new game session for the user."""
    user_id = str(uuid.uuid4())
    session_key = f"user_session:{user_id}"
    session_data = {
        'score': 0,
        'created_at': time.time()
    }
    # Store session data in Redis with expiration
    redis_client.hset(session_key, mapping=session_data)
    redis_client.expire(session_key, SESSION_DURATION)
    logging.info(f"New game started with user_id: {user_id}")
    return jsonify({
        "user_id": user_id,
        "score": 0,
        "session_duration": SESSION_DURATION
    })

@app.route('/update_score', methods=['POST'])
def update_score():
    """Update the user's score."""
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid request data.", "score": 0}), 400

    user_id = data.get('user_id')
    if not user_id:
        return jsonify({"error": "User ID not provided.", "score": 0}), 400

    session_key = f"user_session:{user_id}"
    # Check if session exists
    if not redis_client.exists(session_key):
        return jsonify({
            "error": "Session expired or invalid. Please restart the game.",
            "score": 0,
            "session_expired": True
        }), 401

    # Retrieve session data
    session_data = redis_client.hgetall(session_key)
    if not session_data:
        return jsonify({
            "error": "Session data missing. Please restart the game.",
            "score": 0,
            "session_expired": True
        }), 401

    # Check session expiration
    created_at = float(session_data.get(b'created_at', 0))
    session_age = time.time() - created_at
    if session_age > SESSION_DURATION:
        redis_client.delete(session_key)
        return jsonify({
            "error": "Session expired. Please restart the game.",
            "score": 0,
            "session_expired": True
        }), 401

    # Implement rate limiting per user_id
    rate_limit_key = f"rate_limit:{user_id}"
    current_count = redis_client.incr(rate_limit_key)
    if current_count == 1:
        # Set expiration on rate limit key
        redis_client.expire(rate_limit_key, RATE_LIMIT_WINDOW)
    elif current_count > RATE_LIMIT:
        # Reset score
        redis_client.hset(session_key, 'score', 0)
        return jsonify({
            "error": "Too many requests. Anti-cheat triggered! Your score has been reset.",
            "score": 0
        }), 429

    # Points validation logic
    score = int(session_data.get(b'score', 0))
    total_valid_points = 0
    for key, value in data.items():
        if key.lower() == "bugs_squashed":
            try:
                point_value = float(value)
            except ValueError:
                redis_client.hset(session_key, 'score', 0)
                return jsonify({
                    "error": "Invalid points value detected. Anti-cheat is investigating.",
                    "score": 0
                }), 400
            if point_value == 1:
                total_valid_points += 1
            else:
                redis_client.hset(session_key, 'score', 0)
                return jsonify({
                    "error": f"Invalid point value ({point_value}). Anti-cheat is suspicious.",
                    "score": 0
                }), 400

    if total_valid_points > 4096:
        redis_client.hset(session_key, 'score', 0)
        return jsonify({
            "error": f"Anomaly detected: {total_valid_points} points in 1 second. Score reset!",
            "score": 0
        }), 400
    else:
        # Update the user's score in Redis
        score += total_valid_points
        redis_client.hset(session_key, 'score', score)
        if score >= 100000:
            return jsonify({"message": flag, "score": score})
        else:
            return jsonify({
                "message": f"Score updated by {total_valid_points} points.",
                "score": score,
                "session_expired": False
            })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
```

{% endcode %}
