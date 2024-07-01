---
name: She Sells C Shells (2023)
event: HackTheBox Cyber Apocalypse - Intergalactic Chase CTF 2023
category: Rev
description: Writeup for She Sells C Shells (Rev) - HackTheBox Cyber Apocalypse - Intergalactic Chase CTF (2023) 💜
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

# She Sells C Shells

## Description

> You've arrived in the Galactic Archive, sure that a critical clue is hidden here. You wait anxiously for a terminal to boot up, hiding in the shadows from the guards hunting for you. Unfortunately, it looks like you'll need a password to get what you need without setting off the alarms...

## Solution

We run a shell and have a `get_flag` option that takes a password.

{% code overflow="wrap" %}
```bash
ltrace ./shell
printf("ctfsh-$ ")                                                      = 8
fgets(ctfsh-$ test
"test\n", 1024, 0x7fe582e2e980)                                   = 0x7ffd880fa6b0
strchr("test\n", '\n')                                                  = "\n"
strdup("test")                                                          = 0x555a30952ac0
strtok("test", " ")                                                     = "test"
strtok(nil, " ")                                                        = nil
strcmp("ls", "test")                                                    = -8
strcmp("whoami", "test")                                                = 3
strcmp("cat", "test")                                                   = -17
strcmp("getflag", "test")                                               = -13
strcmp("help", "test")                                                  = -12
fprintf(0x7fe582e2f5c0, "No such command `%s`\n", "test"No such command `test`
)               = 23
free(0x555a30952ac0)                                                    = <void>
printf("ctfsh-$ ")                                                      = 8
fgets(ctfsh-$
```
{% endcode %}

`get_flag` looks like.

{% code overflow="wrap" %}
```c
fgets((char *)&input,256,stdin);
  for (i = 0; i < 77; i = i + 1) {
    *(byte *)((long)&input + (long)(int)i) = *(byte *)((long)&input + (long)(int)i) ^ m1[(int)i];
  }
  local_14 = memcmp(&input,t,77);
  if (local_14 == 0) {
    for (j = 0; j < 77; j = j + 1) {
      *(byte *)((long)&input + (long)(int)j) = *(byte *)((long)&input + (long)(int)j) ^ m2[(int)j];
    }
    printf("Flag: %s\n",&input);
    uVar1 = 0;
  }
  else {
    uVar1 = 0xffffffff;
  }
  return uVar1;
```
{% endcode %}

Setup a breakpoint at the memcmp and find out what `t` equals.

{% code overflow="wrap" %}
```bash
breakrva 0x194d

x/64wx 0x555555556200
0x555555556200 <t>:	0x99b74a2c	0x7870e5a3	0xd9976e93	0xbd386d47
0x555555556210 <t+16>:	0x9985bbff	0xab4ae16f	0xa87bc374	0xecd79fb2
0x555555556220 <t+32>:	0xb263cdeb	0x84e12339	0xc6099692	0xfa58f299
0x555555556230 <t+48>:	0x5e6f6fcb	0x132bbe1f	0x99a9a58e	0x708fab93
0x555555556240 <t+64>:	0x3ec4c01c	0x3593fea6	0x10c9c390	0x000000e9
0x555555556250:	0x00000000	0x00000000	0x00000000	0x00000000
0x555555556260 <m2>:	0xe2f51e64	0x1b4497c0	0xbef95ff8	0x8e485d18
0x555555556270 <m2+16>:	0xf1f6e491	0x9e268d5c	0xf702a12b	0xb3e4f7c6
0x555555556280 <m2+32>:	0xed57fe98	0xf6d14b4a	0xc609eba1	0xfa58f299
0x555555556290 <m2+48>:	0x5e6f6fcb	0x132bbe1f	0x99a9a58e	0x708fab93
0x5555555562a0 <m2+64>:	0x3ec4c01c	0x3593fea6	0x10c9c390	0x736150e9
```
{% endcode %}

So it's like this:

-   our 77 byte input is XORd with `m1`
-   the output is compared with `t`
-   if it matches, our input is XORd with `m2`
-   the result is our flag

Plan of action:

-   XOR `t` with `m2` to recover out `input` (plaintext)

Copied and pasted the ghidra assembly and asked ChatGPT to extract the `XXh` values.

{% code overflow="wrap" %}
```txt
t: 2c4ab799a3e57078936e97d9476d38bdffbb85996fe14aab74c37ba8b29fd7ecebcd63b23923e184929609c699f258facb6f6f5e1fbe2b138ea5a99993ab8f701cc0c43ea6fe933590c3c910e9

m2:641ef5e2c097441bf85ff9be185d488e91e4f6f15c8d269e2ba102f7c6f7e4b398fe57ed4a4bd1f6a1eb09c699f258facb6f6f5e1fbe2b138ea5a99993ab8f701cc0c43ea6fe933590c3c910e9
```
{% endcode %}

So we [XOR](<https://gchq.github.io/CyberChef/#recipe=From_Hex('Auto')XOR(%7B'option':'Hex','string':'641ef5e2c097441bf85ff9be185d488e91e4f6f15c8d269e2ba102f7c6f7e4b398fe57ed4a4bd1f6a1eb09c699f258facb6f6f5e1fbe2b138ea5a99993ab8f701cc0c43ea6fe933590c3c910e9'%7D,'Standard',false)&input=MmM0YWI3OTlhM2U1NzA3ODkzNmU5N2Q5NDc2ZDM4YmRmZmJiODU5OTZmZTE0YWFiNzRjMzdiYThiMjlmZDdlY2ViY2Q2M2IyMzkyM2UxODQ5Mjk2MDljNjk5ZjI1OGZhY2I2ZjZmNWUxZmJlMmIxMzhlYTVhOTk5OTNhYjhmNzAxY2MwYzQzZWE2ZmU5MzM1OTBjM2M5MTBlOQ>) them and get the flag!

Flag: `HTB{cr4ck1ng_0p3n_sh3ll5_by_th3_s34_sh0r3}`
