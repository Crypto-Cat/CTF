# Demo script for 'Introduction to JWT Attacks' video: https://youtu.be/GIq3naOLrTg
import jwt
import base64


def verify_token(token):
    try:
        decoded_token = jwt.decode(token, secret_key, algorithms=["HS256"])
        print("Verification Result: Token is valid.")
    except jwt.exceptions.InvalidSignatureError:
        print("Verification Result: Signature mismatch. Token is invalid.")


# Define a secret key (should be kept secure in a production environment)
secret_key = "intigriti"

# Define a payload (claims) to be included in the token
payload = {"user_id": 420, "username": "cryptocat", "role": "user"}

# Generate a JWT token (sign)
token = jwt.encode(payload, secret_key, algorithm="HS256")
print(f"Original token: {token}\n")

# Verify the token (verify)
verify_token(token)

# Attempt to modify the role to "admin" (JWT manipulation)
header, payload, signature = token.split('.')
decoded_payload = base64.urlsafe_b64decode(payload + '=' * (-len(payload) % 4))
modified_payload = decoded_payload.replace(b'"role":"user"', b'"role":"admin"')
modified_payload_b64 = base64.urlsafe_b64encode(modified_payload).rstrip(b'=').decode()

# Generate a new token with the modified payload (re-encode)
modified_token = f"{header}.{modified_payload_b64}.{signature}"
print(f"\nModified token: {modified_token}\n")

# Verify the token (verify)
verify_token(modified_token)