---
CTF: Imaginary CTF 2023
Challenge Name: inspection
Category: Web
Date: 22/07/23
Author: Eth007
Points: 100
Solves: 473
---

### Description
>Here's a freebie: the flag is ictf.

As the title suggests, we can use the `inspector` (F12) and have a look around.

We'll quickly see the description HTML looks like this.
```html
<p m4rkdown_parser_fail_1a211b44="">Here's a freebie: the flag is ictf.</p>
```

We have our flag.
```txt
ictf{m4rkdown_parser_fail_1a211b44}
```