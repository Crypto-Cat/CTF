from pyshark import *
import re

capture = FileCapture('traffic.pcap')

# Fake flag will be updated as pcap processed
flag = list("CTF{deadbeefdeadc0dedeadbeefdeadc0de}")

for i, packet in enumerate(capture):
    try:
        # Grab SQL queries
        sql_query = packet.tds.query
        if 'SUBSTRING' in sql_query:
            # If the response length is 200 then condition is true
            if capture[i + 1].length == '200':
                # Extract the char position and decimal value
                extracted = re.match(r'.*,(\d+),\d+\)\)\>(\d+)', sql_query, re.M | re.I)
                char_index = extracted.group(1)
                char_value = extracted.group(2)
                # Update the flag
                flag[int(char_index) - 1] = chr(int(char_value) + 1)
    except AttributeError as e:
        pass

# Profit?
print(''.join(flag))
