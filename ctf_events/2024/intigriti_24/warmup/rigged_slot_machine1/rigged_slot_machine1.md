---
name: Rigged Slot Machine 1 (2024)
event: Intigriti 1337UP LIVE CTF 2024
category: Warmup
description: Writeup for Rigged Slot Machine 1 (Warmup) - 1337UP LIVE CTF (2024) 💜
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

# Rigged Slot Machine (part 1)

## Video walkthrough

[![VIDEO](https://img.youtube.com/vi/ZKtRuZMqo2o/0.jpg)](https://youtu.be/ZKtRuZMqo2o "Buffer Overflow: Overwriting Stack Variables and Basic Python Scripting")

## Challenge Description

> The casino thinks they've rigged their slots so well, they can give every player $100 free play! Of course, there's always some small print: you can't cash out unless you hit the jackpot and each player only gets 3 minutes playtime

This wasn't a challenge I intended to make, it's the result of an unintended solution in the `Rigged Slot Machine` pwn challenge (patched in part 2) so I figured I'd keep it in as a warmup reversing/programming exercise 🤷‍♂️

## Solution

`checksec` indicates all binary protections are enabled so we can assume it's not a pwn challenge (warmup lol). Perhaps start by testing the basic functionality of the app.

{% code overflow="wrap" %}

```bash
./rigged_slot1
Welcome to the Rigged Slot Machine!
You start with $100. Can you beat the odds?

Enter your bet amount (up to $100 per spin): 10
You lost $10.
Current Balance: $90

Enter your bet amount (up to $100 per spin): 10
You won $40!
Current Balance: $130

Enter your bet amount (up to $100 per spin): 10
You lost $10.
Current Balance: $120

Enter your bet amount (up to $100 per spin): 10
You lost $10.
Current Balance: $110

Enter your bet amount (up to $100 per spin): 10
You won $10!
Current Balance: $120

Enter your bet amount (up to $100 per spin): 100
You won $400!
Current Balance: $520

Enter your bet amount (up to $100 per spin): 100
You lost $100.
Current Balance: $420
```

{% endcode %}

Yes, I made this shortly after returning home from Vegas 😂

Since players only receive the binary (no sauce), let's check the winning condition in `ghidra`.

### Static Analysis

I renamed variables already to make it clearer, here's the `main` function.

{% code overflow="wrap" %}

```c
setup_alarm(180);
balance = 100;
puts("Welcome to the Rigged Slot Machine!");
puts("You start with $100. Can you beat the odds?");
do {
  while( true ) {
    while( true ) {
      bet = 0;
      printf("\nEnter your bet amount (up to $%d per spin): ",100);
      local_10 = __isoc99_scanf(&%d,&bet);
      if (local_10 == 1) break;
      puts("Invalid input! Please enter a numeric value.");
      clear_input();
    }
    if ((bet < 1) || (100 < bet)) break;
    if ((int)balance < bet) {
      printf("You cannot bet more than your current balance of $%d!\n",(ulong)balance);
    }
    else {
      play(bet,&balance);
      if (133742 < (int)balance) {
        payout(&balance);
      }
    }
  }
  printf("Invalid bet amount! Please bet an amount between $1 and $%d.\n",100);
} while( true );
```

{% endcode %}

The `play` function will spin the slot.

{% code overflow="wrap" %}

```c
outcome = rand();
outcome = outcome % 100;
if (outcome == 0) {
  multiplier = 100;
}
else if (outcome < 10) {
  multiplier = 5;
}
else if (outcome < 15) {
  multiplier = 3;
}
else if (outcome < 20) {
  multiplier = 2;
}
else if (outcome < 30) {
  multiplier = 1;
}
else {
  multiplier = 0;
}
result = bet * multiplier - bet;
```

{% endcode %}

The `payout` function will print the flag.

{% code overflow="wrap" %}

```c
if (*balance < 133743) {
  puts("You can\'t withdraw money until you win the jackpot!");
  exit(-1);
}
file = fopen("flag.txt","r");
if (file == (FILE *)0x0) {
  puts(
      "Flag File is Missing. Problem is Misconfigured, please contact an Admin if you are running this on the shell server."
      );
  exit(0);
}
fgets(flag,0x40,file);
printf("Congratulations! You\'ve won the jackpot! Here is your flag: %s\n",flag);
fclose(file);
```

{% endcode %}

So, what's the problem? Look at those odds! 1/100 spins will get a 100x multiplier 👀

If I run the program 100 times with a starting bet of $100, the chances are one of those spins will win me $10,000 🤑 That's enough capital to continue betting MAX BET (of course we'll get some 2-5x along the way too).

### Solve.py

Here's my solve script. It starts with a $25 bet and then switches to $100 once the balance exceeds $10,000. You can play around with these values and see what works best, e.g. $10 starting bet, then switch to $100 when you reach $5000.

{% code overflow="wrap" %}

```python
import sys
from pwn import *

# Allows switching between local/GDB/remote execution
def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

# Binary filename
exe = './rigged_slot1'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'

# Jackpot threshold
winning_balance = 133742
got_flag = False

while not got_flag:
    # Start the program
    io = start(level='warn')
    balance = 100
    amount = b'25'

    # Skip the initial output
    io.recvlines(3)
    io.sendline(amount)

    count = 1

    while balance > 0 and not got_flag:
        try:
            # Adjust bet amount
            if balance > 10000:
                amount = b'100'
            io.sendlineafter(b':', amount)
            io.recvuntil(b'Current Balance: ')
            balance = int(io.recvline().decode()[1:].strip())
            info(f'balance: {balance}')
            count += 1
            # Check if we've hit the jackpot (remote)
            if balance >= winning_balance:
                warn("Jackpot threshold reached. Attempting to retrieve flag.")
                flag_output = io.recvline().decode()
                info(flag_output)
                got_flag = True
        except EOFError:
            # Capture flag output in case of EOF (local)
            remaining_output = io.recvall(timeout=5).decode()
            if 'Congratulations' in remaining_output:
                warn("Flag captured via EOF handling:")
                info(remaining_output)
                got_flag = True
            break
        except Exception as e:
            warn(f'Error after {count} bets: {str(e)}')
            break

    warn(f'Total bets placed: {count}')
    io.close()
```

{% endcode %}

Interestingly, solving the challenge locally is slightly different to remote. Notice that for the `remote` exploit, we get the flag by checking the winning balance whereas the `local` flag prints with an EOF error. I'm not sure if this is related to pwntools or something else, but maybe it will cause some confusion in the CTF (especially for a warmup challenge) 😬

### Performance

Anyway, testing this locally is fast. Obviously it varies for each run due to the random element but with 3 attempts I got an average of 4 seconds\*, with the fastest being 1s.

{% code overflow="wrap" %}

```bash
[*] balance: 126825
[!] Flag captured via EOF handling:
[*]  You won $9900!
    Current Balance: $136725
    Congratulations! You've won the jackpot! Here is your flag: fake_flag

[!] Total bets placed: 1294

real	0m1.026s
user	0m0.580s
sys	0m0.472s
```

{% endcode %}

\*Note that this is the time for all runs, not the winning run. For example, when you run the script it might lose 100 games in a row before it wins. Some of those games may take a few seconds, but could be longer. In other words, if `time` shows over 180 seconds and you still won, it's because the final game didn't exceed the limit.

Solving remotely certainly takes longer, but it's possible to solve well within the allocated 180 second time limit. In 3 attempts I got an average of 62 seconds, with the fastest being 34s.

{% code overflow="wrap" %}

```bash
[*] balance: 136800
[!] Jackpot threshold reached. Attempting to retrieve flag.
[*] Congratulations! You've won the jackpot! Here is your flag: INTIGRITI{ju57_l1k3_7h47_y0u_4r3_4_m1ll10n41r3!}
[!] Total bets placed: 1446

real	0m33.884s
user	0m0.866s
sys	0m0.678s
```

{% endcode %}

Flag: `INTIGRITI{ju57_l1k3_7h47_y0u_4r3_4_m1ll10n41r3!}`

Note: I have to apologise to some players here. After the event I helped debug a players script and it turns out I didn't leave enough time for those really far from the server (India, Australia etc) with poor connections. I _should_ of tested my solution with a VPN connected in various countries before the event, it didn't occur to me but I know for next time! 💜

[Someone](https://www.linkedin.com/in/gonçalo-melo-6485592a0) found a nice unintended that works on Rigged slot 1. Using careful timing, you could predict the "random" seed and therefore the outcome of each bet 🧠 Check out the [writeup](https://xstf.pt/2024-11-16-RiggedSlotMachine1) 😎
