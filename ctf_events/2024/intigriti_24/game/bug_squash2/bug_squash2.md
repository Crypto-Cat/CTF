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

I'll improve the writeup! check the video walkthrough too 😊

## Solution

-   Description indicates need more than 100,000 points to win
-   Setup Windows proxy 127.0.0.1:8080
-   Setup burp cert to capture HTTPS traffic
    -   Export proxy cert in PKCS format
    -   `Windows > Manage user certificates > Trusted Root Certification Authorities > Certificates > All Tasks > Import`
    -   Traffic will now show in burp
-   Try to modify the traffic, to change the points but there are some conditions:
    -   Anti-cheat resets users score if they send more then 3 request per second
    -   Anti-cheat rejects any point values that aren't 1 (and resets)
    -   Anti-cheat checks that players score didn't jump to an unrealistic number (more than 4096 per request)
        -   Game resets every 2 mins (so by the anti-cheat rules, max they can get is (120 \* 3))
-   The thing about JSON is the [keys are non case-sensitive](https://www.quora.com/Is-JSON-case-sensitive), so you could send `BUGS_SQUASHED` instead of `bugs_squashed` and it wouldn't treated the same.
-   However, if you give that a go, you'll see it _is_ treated the same. It gives a point regardless of the case sensitivity. What if you try and send multiple of the _same_ key but with different case, all while adhering to the 3 requests per second and 1 bug per squash limit!
-   So yes, intended solution is to send `{"user_id": "insert_id", "bugs_squashed": 1, "bUgs_squashed": 1, "buGs_squashed": 1}` etc, where you can send max 4096 variations per request, max 3 requests per second.. Will need to use custom fuzzing script/limit intruder to the anti-cheat requirements

### solve.py

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
    response = session.post('{BASE_URL}/start_game')
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
        '{BASE_URL}/update_score', json=json_data)
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

Flag: `INTIGRITI{64m3_h4ck1n6_4n71ch347_15_4l50_fun!}`
