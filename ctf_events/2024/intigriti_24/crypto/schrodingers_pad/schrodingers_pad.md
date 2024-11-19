---
name: Schrodingers Pad (2024)
event: Intigriti 1337UP LIVE CTF 2024
category: Crypto
description: Writeup for Schrodingers Pad (Crypto) - 1337UP LIVE CTF (2024) 💜
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

# Schrödinger's Pad

## Video walkthrough

[![VIDEO](https://img.youtube.com/vi/9NrmlOBcF1c/0.jpg)](https://youtu.be/9NrmlOBcF1c "One Time Pad (OTP) with a Twist")

## Challenge Description

> Everyone knows you can't reuse a OTP, but throw in a cat and a box.. Maybe it's secure?

If you know me, you know I hate crypto 😑 I wanted to make a challenge for every category though, so here you go..

## Solution

The challenge includes source code, but let's test the basically functionality. Any challenges that include a docker-compose can be started with the `./start.sh` script.

{% code overflow="wrap" %}

```bash
nc localhost 1337
Welcome to Schrödinger's Pad!
Due to its quantum, cat-like nature, this cryptosystem can re-use the same key
Thankfully, that means you'll never be able to uncover this secret message :')

Encrypted (cat state=ERROR! 'cat not in box'): 36021a4c0122024f2d06140947160c3f152b2466262b3405125e08342c49105f277a500206163b761e251d1b0408247729595f3f35446e242304313676316b000f201a192d17581f431748627b2c000a0f0379337c11031b00062f6a144e0c143804501353092a0250264e231f4815032310595b2c20111b593f6d1d073e6b133d5d5d7602165905673f3b732f0721215d21551719391a4c5e2c745852471862

Anyway, why don't you try it for yourself?
cryptocat is the best!
Encrypted (cat state=dead): 474541c44a58c8cd55efc44469474f5dc357d8505a7d
```

{% endcode %}

{% code overflow="wrap" %}

```bash
nc localhost 1337
Welcome to Schrödinger's Pad!
Due to its quantum, cat-like nature, this cryptosystem can re-use the same key
Thankfully, that means you'll never be able to uncover this secret message :')

Encrypted (cat state=ERROR! 'cat not in box'): 1b272d6b41592674373f1106700327406e340254401f311510050427346a283a2148792a3409225a0226053c272a1511520d1f11297a712e0a2d4a0b6142183229120d2e3e1605353100657923361b331660103a7a2c07001504364e1265082e1a357910541827292f2d16565343192c383559230125740d070e5629024d4d570e5d3d14172b18264a3b43512b5d171e042b7d6d583e396a0f2d731f2a6b7658

Anyway, why don't you try it for yourself?
cryptocat is the best!
Encrypted (cat state=dead): d1d7da576ae5da50587346c3f2cddae27ed8cb496967
```

{% endcode %}

Some observations:

-   The encrypted message at the start is different each time we connect
-   The ciphertext generated from our is also different, despite providing the same input

### Source Code Review

Let's get a better understanding what happens when we connect to the server. First thing to note is the key is randomly generate each time we connect (explaining the above observations).

{% code overflow="wrap" %}

```python
KEY = ''.join(random.choices(string.ascii_letters + string.digits, k=160)).encode()
```

{% endcode %}

Next, the flag is encrypted using a `otp` function.

{% code overflow="wrap" %}

```python
client_socket.send(f"Encrypted(cat state=ERROR! 'cat not in box'):
	                {otp(FLAG.encode(), KEY).hex()}\n".encode())
```

{% endcode %}

Finally, it takes a plaintext message (up to 160 bytes) from the user and encrypts it.

{% code overflow="wrap" %}

```python
cat_state = random.choice([0, 1])
ciphertext = otp(plaintext, KEY)
c_ciphertext = check_cat_box(ciphertext, cat_state)
cat_state_str = "alive" if cat_state == 1 else "dead"
```

{% endcode %}

Let's have a look at the two functions. First is `otp`

{% code overflow="wrap" %}

```python
def otp(p, k):
    k_r = (k * ((len(p) // len(k)) + 1))[:len(p)]
    return bytes([p ^ k for p, k in zip(p, k_r)])
```

{% endcode %}

It might look fancy, but it's simply XORing the plaintext with the key. Next is `check_cat_box`\*

{% code overflow="wrap" %}

```python
def check_cat_box(ciphertext, cat_state):
    c = bytearray(ciphertext)
    if cat_state == 1:
        for i in range(len(c)):
            c[i] = ((c[i] << 1) & 0xFF) ^ 0xAC
    else:
        for i in range(len(c)):
            c[i] = ((c[i] >> 1) | (c[i] << 7)) & 0xFF
            c[i] ^= 0xCA
    return bytes(c)
```

{% endcode %}

It performs some bitwise operations (shift and XOR) depending on the `cat_state`, which is also randomly determined.

\*Note that the flag doesn't go through this function, hence "cat not in box" message

### Many Time Pad

One Time Pad's are secure, when the key is truly random. The issues arise when the key is used more than once. That's because XOR is a reversible operation (see warmup: IrrORversible) and with any two pieces of information, we can recover the third.

Since we have some plaintext and the resulting ciphertext, we can XOR them to recover the key. Now, we can recover any other plaintexts that were encrypted with the key, e.g. the flag.

It's made slightly more difficult as a result of the cat/box related operations, but you can manually reverse these or use a script.

_Actually_, this wasn't my intention for the challenge - as you'll probably see from my solve script and the video walkthrough. I hoped players would recover `(p1 ^ p2)` from `(c1 ^ c2)` and then XOR `(p1 ^ p2)` with `p2` to recover `p1`. It's doable if we remove the user input and just provide two long ciphertexts, but I don't have time to make changes now and the writeup/video is already done. Beside, I told you already I hate crypto 🙃

### Solve.py

{% code overflow="wrap" %}

```python
import socket
import binascii

# Step 3a: Reverse "alive" transformation
def reverse_modify_alive(ciphertext):
    modified = bytearray(ciphertext)
    for i in range(len(modified)):
        modified[i] = ((modified[i] ^ 0xAC) >> 1) & 0xFF
    return bytes(modified)

# Step 3b: Reverse "dead" transformation
def reverse_modify_dead(ciphertext):
    modified = bytearray(ciphertext)
    for i in range(len(modified)):
        modified[i] ^= 0xCA
        modified[i] = ((modified[i] << 1) | (modified[i] >> 7)) & 0xFF
    return bytes(modified)

# XOR operation to combine decrypted data with known plaintext
def xor_bytes(data1, data2):
    return bytes([b1 ^ b2 for b1, b2 in zip(data1, data2)])

# Step 1 & 2: Connect to the server, send plaintext, and receive encrypted data
def interact_with_server(server_ip, server_port, plaintext):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((server_ip, server_port))

    # Receive initial message and extract the secret message (c1)
    welcome_message = s.recv(4096).decode()
    print(welcome_message)

    try:
        encrypted_hex = welcome_message.split(
            "Encrypted (cat state=ERROR! 'cat not in box'): ")[-1].strip().split()[0]
        if len(encrypted_hex) % 2 != 0:
            encrypted_hex = encrypted_hex[:-1]
        c1 = binascii.unhexlify(encrypted_hex)
    except (IndexError, binascii.Error) as e:
        print(f"Error extracting the secret message: {e}")
        s.close()
        return None, None, None

    # Send plaintext (m2) to the server
    s.send(plaintext.encode())

    # Receive encrypted data (c2) and cat state
    try:
        response = s.recv(1024).decode().strip()
        print(response)
        cat_state = response.split("Encrypted (cat state=")[-1].split("): ")[0]
        encrypted_hex = response.split(
            "Encrypted (cat state=")[-1].split("): ")[1]
        if len(encrypted_hex) % 2 != 0:
            encrypted_hex = encrypted_hex[:-1]
        c2 = binascii.unhexlify(encrypted_hex)
    except (IndexError, binascii.Error) as e:
        print(f"Error extracting the encrypted response: {e}")
        s.close()
        return None, None, None

    s.close()
    return c1, c2, cat_state

# Main decryption process
def decrypt():
    server_ip = 'localhost'
    server_port = 1337

    # Step 1: Prepare the known 160-byte plaintext (m2)
    m2 = 'The sun dipped below the horizon, painting the sky in hues of pink and orange, as a cool breeze rustled through the trees, signaling the end of a peaceful day.'

    # Step 2: Get the encrypted secret message (c1) and response (c2) from the server
    c1, c2, cat_state = interact_with_server(server_ip, server_port, m2)

    if c1 is None or c2 is None or cat_state is None:
        print("Failed to retrieve or process data from the server.")
        return

    # Step 3: Reverse the transformation on c2 based on the cat state
    decrypted_c2 = reverse_modify_alive(
        c2) if cat_state == "alive" else reverse_modify_dead(c2)

    # Step 4: XOR c1 and c2 to get m1 ^ m2
    m1_xor_m2 = xor_bytes(c1, decrypted_c2)

    # Step 5: XOR the result with m2 to recover m1
    recovered_m1 = xor_bytes(m1_xor_m2, m2.encode())

    # Print the recovered secret message (m1)
    print(
        f"\nRecovered secret message (m1): {recovered_m1.decode(errors='ignore')}\n")

if __name__ == "__main__":
    decrypt()
```

{% endcode %}

As mentioned in the last section, the solve script goes the long, but originally intended way. It's easiest just to do `c2 ^ p2 = k` and then `c1 ^ k = p1`.

{% code overflow="wrap" %}

```bash
python solve.py
Welcome to Schrödinger's Pad!
Due to its quantum, cat-like nature, this cryptosystem can re-use the same key
Thankfully, that means you'll never be able to uncover this secret message :')

Encrypted (cat state=ERROR! 'cat not in box'): 1906264d1130106400540909532937107f42206815332906305f0a24376d163505434e3d1024424824075808210b2413361b29031f424147222c203d6337743f5857581517503b251d326d79001d212272152f253f0c1125303f0c183578040e1b576120661f24223210492451614b28374443570232571a5c526a1c072d78513c3935711736570c61381a6c103a1625555814691d5703670817591a1f784c57

Anyway, why don't you try it for yourself?

Encrypted (cat state=dead): 4b4a516cc15c47f8cb62c6c5c1d0f64954e4df55e9dbda427365ccd6565145d0676dc541c45de94ad94d4141daca7bead5cdf946c0ed4ee95dd7f351dbf8d8d9e766c1cacac0f15844d15cd5dc7560cfe979496240c6dfc9e0c34b6442dbcbebc469d344df415e78ddcc475e6adf4bffd1e6c94646d0c34f6947ffc84f53d7c2c8d6d5d162dde5cd7ad049dee6d4c07a62c1eedcc367c35ac040664347da6b

Recovered secret message (m1): Not the flag you're searching for, Keep looking close, there's plenty more. INTIGRITI{TODO} A clue I might be, but not the key, The flag is hidden, not in me!!
```

{% endcode %}

Repeat against remote for the real flag!

Flag: `INTIGRITI{d34d_0r_4l1v3}`
