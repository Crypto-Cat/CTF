---
name: BucketWars (2024)
event: CSAW CTF 2024
category: Web
description: Writeup for BucketWars (Web) - CSAW CTF (2024) 💜
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

# BucketWars

## Description

> let's keep our storage simple -- and remember we don't make mistakes in these parts.

## Solution

Visit website and find five different versions at `/versions.html`.

{% code overflow="wrap" %}

```
https://bucketwars.ctf.csaw.io/index_v1.html
https://bucketwars.ctf.csaw.io/index_v2.html
https://bucketwars.ctf.csaw.io/index_v3.html
https://bucketwars.ctf.csaw.io/index_v4.html
https://bucketwars.ctf.csaw.io/index.html
```

{% endcode %}

Error when trying to access an invalid file, e.g. https://bucketwars.ctf.csaw.io/dgdfgdfgfdg.html

{% code overflow="wrap" %}

```
404 Not Found

    Code: NoSuchKey
    Message: The specified key does not exist.
    Key: dgdfgdfgfdg.html
    RequestId: J5QS9TW2YM0210EH
    HostId: 8Yt6lsFV9VR0evraLVRz7D0sEwIN4AzW6eQnjEBMAdOGMu80sI/PiVRqAYrfmLEb+E+8DuJihAo=

An Error Occurred While Attempting to Retrieve a Custom Error Document

    Code: NoSuchKey
    Message: The specified key does not exist.
    Key: https://s3.us-east-2.amazonaws.com/bucketwars.ctf.csaw.io/404.jpg
```

{% endcode %}

Can try to list the s3 bucket contents, but no permissions.

{% code overflow="wrap" %}

```bash
aws s3 ls s3://bucketwars.ctf.csaw.io/ --no-sign-request

An error occurred (AccessDenied) when calling the ListObjectsV2 operation: Access Denied
```

{% endcode %}

The most recent version (v5) has a hint:

> Looking deeper into the stolen bucket only reveals past versions of our own selves one might muse

{% code overflow="wrap" %}

```bash
aws s3api list-object-versions --bucket bucketwars.ctf.csaw.io --no-sign-request > output.txt
```

{% endcode %}

There's 300 lines of JSON but here's a snippet.

{% code overflow="wrap" %}

```json
{
	"ETag": "\"07bb73d00569d07588c0b5661438d9d8\"",
	"Size": 1118,
	"StorageClass": "STANDARD",
	"Key": "index_v1.html",
	"VersionId": "xueLuUGnF1kS6dcOaspeUUZN0N4Cdlsq",
	"IsLatest": true,
	"LastModified": "2024-08-05T01:59:50+00:00"
},
{
	"ETag": "\"d3f2f46b2f1814b636cb1c7991a1a328\"",
	"Size": 1290,
	"StorageClass": "STANDARD",
	"Key": "index_v1.html",
	"VersionId": "ToA1N09DluJkPVFATO6IwOTZzhDkva09",
	"IsLatest": false,
	"LastModified": "2024-08-05T00:26:48+00:00"
},
{
	"ETag": "\"5c3665517b3e538158ab09b15a647dbb\"",
	"Size": 1456,
	"StorageClass": "STANDARD",
	"Key": "index_v1.html",
	"VersionId": "zCVAK4kjygiOnWWGGi1BZOR87Ef09Z0L",
	"IsLatest": false,
	"LastModified": "2024-08-05T00:20:20+00:00"
},
{
	"ETag": "\"9a5824c100e6975c203e2ae517c9ec0d\"",
	"Size": 1555,
	"StorageClass": "STANDARD",
	"Key": "index_v1.html",
	"VersionId": "CFNz2JPIIJfRlNfnVx8a45jgh0J90KxS",
	"IsLatest": false,
	"LastModified": "2024-08-05T00:20:08+00:00"
},
{
	"ETag": "\"130f7fdffa9c3a0e24853b651dfe07ac\"",
	"Size": 1571,
	"StorageClass": "STANDARD",
	"Key": "index_v1.html",
	"VersionId": "t6G6A20JCaF5nzz6KuJR6Pj1zePOLAdB",
	"IsLatest": false,
	"LastModified": "2024-08-05T00:19:57+00:00"
}
```

{% endcode %}

We have five different versions of the `index_v1.html` file, but all the other four versions only have a single entry.

It's also worth noting that `v1` was the only page with no image, only the string: `YIKES`. Presumably, we need to recover the old versions of `index_v1.html` 🤔

We already have the latest, so we try the other 4. The first two had nothing but version 4, which is interesting.

{% code overflow="wrap" %}

```bash
aws s3api get-object --bucket bucketwars.ctf.csaw.io --key index_v1.html --version-id CFNz2JPIIJfRlNfnVx8a45jgh0J90KxS index_v1_version4.html --no-sign-request
```

{% endcode %}

{% code overflow="wrap" %}

```json
{
    "AcceptRanges": "bytes",
    "LastModified": "2024-08-05T00:20:08+00:00",
    "ContentLength": 1555,
    "ETag": "\"9a5824c100e6975c203e2ae517c9ec0d\"",
    "VersionId": "CFNz2JPIIJfRlNfnVx8a45jgh0J90KxS",
    "ContentType": "text/html",
    "ServerSideEncryption": "AES256",
    "Metadata": {}
}
```

{% endcode %}

It contains a password in the HTML: `versions_leaks_buckets_oh_my`.

{% code overflow="wrap" %}

```html
<!-- Note to self: be sure to delete this password: versions_leaks_buckets_oh_my -->
```

{% endcode %}

Version 5 contains a new URL.

{% code overflow="wrap" %}

```html
<img src="https://asdfaweofijaklfdjkldfsjfas.s3.us-east-2.amazonaws.com/sand-pit-1345726_640.jpg" />
```

{% endcode %}

The last bit took me too long because I didn't expect stego in a web challenge 😆 Pair those two pieces of information with `steghide`, and you get the flag.

{% code overflow="wrap" %}

```bash
steghide extract -sf sand-pit-1345726_640.jpg -p versions_leaks_buckets_oh_my
wrote extracted data to "flag.txt".
```

{% endcode %}

Flag: `csawctf{cl0d_Bu4K3tz_AR3_F4Ir_g$m3}`
