---
name: Inspection (2023)
event: Imaginary 2023
category: Web
description: Writeup for Inspection (Web) - Imaginary (2023) 💜
layout:
    title:
        visible: true
    description:
        visible: true
    tableOfContents:
        visible: false
    outline:
        visible: true
    pagination:
        visible: true
---

# Inspection

## Description

> Here's a freebie: the flag is ictf.

As the title suggests, we can use the `inspector` (F12) and have a look around.

We'll quickly see the description HTML looks like this.

```html
<p m4rkdown_parser_fail_1a211b44="">Here's a freebie: the flag is ictf.</p>
```

We have our flag.

Flag: `ictf{m4rkdown_parser_fail_1a211b44}`
