from pwn import *
import zlib

wordlist = open('/usr/share/wordlists/rockyou.txt', 'r')
admin_pw = -432570933
initial_pw = 'skylark'

for count in range(99999999999):
    password = str(count)
    hashed_pw = zlib.crc32(password.encode())
    print(hashed_pw)
    # If we get a match, quit!
    if hashed_pw == admin_pw:
        print("Success! Correct password was: " + password)
        wordlist.close()
        quit()

    # Track progress / performance
    if((count + 1) % 100 == 0):
        print(str(count + 1) + " attempts so far..")

# Maybe we need new password list?
print("Failed to find correct password :(")
wordlist.close()
