from pwn import *
import requests
from bs4 import BeautifulSoup

context.log_level = 'debug'
url = 'https://crumbs.web.actf.co/'

response = requests.get(url)  # Initial request

# Loop until we see the flag (1000 times)
while 'actf' not in response.text:
    # Extract the next slug from <p>
    extracted = BeautifulSoup(response.text, features="lxml").p.contents[0][6:]
    debug('extracted: %s', extracted)
    # Visit the new page
    response = requests.get(url + extracted)

# Print the response if we got the flag
extracted = BeautifulSoup(response.text, features="lxml").p.contents[0]
warn(extracted)
