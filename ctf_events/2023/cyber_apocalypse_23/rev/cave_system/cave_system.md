---
name: Cave System (2023)
event: HackTheBox Cyber Apocalypse - Intergalactic Chase CTF 2023
category: Rev
description: Writeup for Cave System (Rev) - HackTheBox Cyber Apocalypse - Intergalactic Chase CTF (2023) 💜
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

# Cave System

## Description

> Deep inside a cave system, 500 feet below the surface, you find yourself stranded with supplies running low. Ahead of you sprawls a network of tunnels, branching off and looping back on themselves. You don't have time to explore them all - you'll need to program your cave-crawling robot to find the way out...

## Solution

Ghidra shows quite complex conditions in flag checker.

{% code overflow="wrap" %}
```c
printf("What route will you take out of the cave? ");
fgets((char *)&local_88,0x80,stdin);
iVar1 = memcmp(&local_88,&DAT_00102033,4);
if (((((((iVar1 == 0) && ((byte)(local_78._5_1_ * (char)local_58) == '\x14')) &&
     ((byte)((byte)local_68 - local_68._4_1_) == -6)) &&
    (((((((byte)(local_68._5_1_ - local_70._2_1_) == -0x2a &&
         ((byte)((byte)local_78 - (char)local_58) == '\b')) &&
        (((char)(local_58._7_1_ - (char)local_80) == -0x2b &&
         (((byte)(local_70._2_1_ * local_88._7_1_) == -0x13 &&
          ((char)(local_88._4_1_ * (char)local_70) == -0x38)))))) &&
       ((local_68._2_1_ ^ local_70._4_1_) == 0x55)) &&
      (((((byte)(local_70._6_1_ - local_58._7_1_) == '4' &&
         ((byte)(local_50._3_1_ + local_58._2_1_) == -0x71)) &&
        ((byte)(local_60._4_1_ + local_70._3_1_) == -0x2a)) &&
       (((local_78._1_1_ ^ local_80._6_1_) == 0x31 &&
        ((byte)((byte)local_50 * local_78._4_1_) == -0x54)))))) &&
     (((((byte)(local_50._2_1_ - local_70._2_1_) == -0x3e &&
        (((local_70._2_1_ ^ local_88._6_1_) == 0x2f &&
         ((local_80._6_1_ ^ local_68._7_1_) == 0x5a)))) &&
       ((local_60._4_1_ ^ local_68._7_1_) == 0x40)) &&
      ((((((byte)local_60 == local_70._2_1_ &&
          ((byte)(local_78._7_1_ + local_58._1_1_) == -0x68)) &&
         ((byte)(local_78._7_1_ * local_50._3_1_) == 'h')) &&
        (((byte)(local_88._1_1_ - local_70._4_1_) == -0x25 &&
         ((byte)((char)local_70 - local_70._5_1_) == -0x2e)))) &&
       (((char)(local_68._6_1_ - (char)local_70) == '.' &&
        ((((byte)local_68 ^ local_78._6_1_) == 0x1a &&
         ((byte)(local_60._4_1_ * local_88._4_1_) == -0x60)))))))))))) &&
   ((((((byte)(local_68._6_1_ * local_70._3_1_) == '^' &&
       ((((byte)(local_80._7_1_ - (byte)local_60) == -0x38 &&
         ((local_58._1_1_ ^ local_58._5_1_) == 0x56)) &&
        ((local_70._2_1_ ^ local_60._5_1_) == 0x2b)))) &&
      ((((((local_58._6_1_ ^ local_80._1_1_) == 0x19 &&
          ((byte)(local_70._4_1_ - local_60._7_1_) == '\x1a')) &&
         (((byte)(local_58._2_1_ + local_78._3_1_) == -0x5f &&
          (((byte)(local_68._5_1_ + local_50._1_1_) == 'V' &&
           ((local_70._5_1_ ^ local_78._2_1_) == 0x38)))))) &&
        ((local_60._4_1_ ^ local_50._4_1_) == 9)) &&
       ((((((char)(local_80._7_1_ * local_68._6_1_) == 'y' &&
           ((local_68._5_1_ ^ local_70._6_1_) == 0x5d)) &&
          ((byte)(local_88._2_1_ * (byte)local_68) == '\\')) &&
         (((byte)(local_80._2_1_ * local_78._2_1_) == '9' && (local_70._5_1_ == local_78._5_1_))
         )) && (((byte)(local_68._3_1_ * local_78._5_1_) == '/' &&
                (((byte)((char)local_80 * local_68._5_1_) == -0x55 &&
                 ((byte)(local_68._7_1_ + local_70._2_1_) == -0x6d)))))))))) &&
     (((((((local_70._2_1_ ^ local_68._2_1_) == 0x73 &&
          ((((local_78._4_1_ ^ local_70._7_1_) == 0x40 &&
            ((byte)(local_70._1_1_ + (byte)local_78) == -0x57)) &&
           ((local_68._7_1_ ^ local_50._3_1_) == 0x15)))) &&
         ((((byte)((byte)local_88 + local_50._3_1_) == 'i' &&
           ((byte)(local_68._2_1_ + local_60._6_1_) == -0x5b)) &&
          (((local_70._6_1_ ^ local_58._4_1_) == 0x37 &&
           (((byte)((byte)local_88 * local_70._4_1_) == '\b' &&
            ((byte)(local_68._2_1_ - (byte)local_50) == -0x3b)))))))) &&
        ((byte)(local_78._2_1_ + local_50._4_1_) == -0x1c)) &&
       (((((local_68._3_1_ ^ (byte)local_60) == 0x6e &&
          ((byte)((byte)local_50 * (byte)local_78) == -0x54)) &&
         ((byte)(local_58._6_1_ - local_60._7_1_) == '\r')) &&
        ((((byte)(local_70._6_1_ + local_58._7_1_) == -100 &&
          ((byte)(local_88._6_1_ + local_68._1_1_) == -0x2c)) &&
         (((byte)(local_88._7_1_ * local_70._5_1_) == -0x13 &&
          ((((byte)local_50 ^ local_70._5_1_) == 0x38 &&
           ((byte)(local_88._1_1_ * local_68._5_1_) == 'd')))))))))) &&
      ((((byte)local_50 ^ local_50._2_1_) == 0x46 &&
       (((((((char)(local_88._2_1_ * local_78._3_1_) == '&' &&
            ((local_70._2_1_ ^ local_78._6_1_) == 0x2b)) &&
           ((byte)(local_88._1_1_ + local_88._7_1_) == -0x79)) &&
          (((local_70._3_1_ ^ (byte)local_88) == 0x2a &&
           ((byte)(local_78._5_1_ - local_88._1_1_) == '\v')))) &&
         ((byte)(local_70._3_1_ + local_58._6_1_) == -0x32)) &&
        (((local_78._1_1_ ^ local_80._5_1_) == 0x3b &&
         ((byte)(local_78._3_1_ - local_50._2_1_) == '\x12')))))))))) &&
    ((((local_78._1_1_ == local_80._2_1_ &&
       ((((byte)(local_80._6_1_ - local_50._2_1_) == 'M' &&
         ((byte)(local_60._2_1_ * local_58._4_1_) == 'N')) && (local_58._2_1_ == (byte)local_68)
        ))) && (((local_60._7_1_ ^ local_58._3_1_) == 0x38 &&
                ((char)(local_68._6_1_ + local_70._1_1_) == -0x6c)))) &&
     ((byte)(local_60._1_1_ + local_58._4_1_) == -0x31)))))) &&
  ((((local_60._4_1_ == local_78._4_1_ && ((char)(local_80._4_1_ + local_70._1_1_) == 'f')) &&
    (((byte)(local_50._4_1_ + local_68._4_1_) == -0xf &&
     ((((byte)(local_60._1_1_ - local_78._5_1_) == '\x11' &&
       ((byte)(local_68._4_1_ - local_58._1_1_) == 'D')) &&
      ((byte)(local_80._1_1_ - local_68._3_1_) == 'D')))))) &&
   ((((local_58._5_1_ ^ local_58._3_1_) == 1 && ((local_68._2_1_ ^ local_50._1_1_) == 0xd)) &&
    ((((byte)(local_80._3_1_ - local_70._4_1_) == -0x15 &&
      (((((char)(local_78._7_1_ + (char)local_70) == -0x67 &&
         ((byte)((char)local_70 + local_80._5_1_) == -0x6b)) &&
        (((byte)(local_80._4_1_ - (byte)local_88) == -0x17 &&
         (((((byte)(local_68._2_1_ + local_70._7_1_) == '`' &&
            ((byte)(local_88._5_1_ + local_58._5_1_) == -0x6a)) &&
           ((byte)(local_58._1_1_ * local_60._2_1_) == '`')) &&
          (((byte)((char)local_58 * local_78._5_1_) == '\x14' &&
           ((byte)(local_70._3_1_ - local_58._4_1_) == '\x03')))))))) &&
       ((byte)(local_50._1_1_ + local_78._4_1_) == -0x6b)))) &&
     ((((byte)(local_80._2_1_ * local_58._5_1_) == -0x26 &&
       ((byte)(local_88._1_1_ + local_60._1_1_) == -0x3c)) &&
      (((byte)(local_60._7_1_ - local_88._1_1_) == '\v' &&
       (((local_60._3_1_ == local_78._3_1_ && ((byte)(local_68._7_1_ + local_60._7_1_) == -0x6d)
         ) && ((byte)(local_80._4_1_ * local_50._2_1_) == 'Q')))))))))))))) &&
 (((((byte)((char)local_80 * local_70._2_1_) == 'A' &&
    ((byte)(local_60._6_1_ - local_70._7_1_) == 'E')) &&
   ((byte)(local_88._7_1_ + local_68._5_1_) == 'h')) &&
  (((((char)(local_68._4_1_ + local_88._4_1_) == -0x44 &&
     ((byte)(local_70._7_1_ + (byte)local_68) == -0x5e)) &&
    (((char)(local_70._1_1_ + local_88._5_1_) == 'e' &&
     ((((byte)(local_60._3_1_ * local_70._5_1_) == -0x13 &&
       ((local_80._5_1_ ^ local_60._5_1_) == 0x10)) &&
      ((char)((char)local_58 - local_80._4_1_) == ';')))))) &&
   (((((char)(local_78._7_1_ - (char)local_80) == '\t' &&
      ((local_88._7_1_ ^ local_60._2_1_) == 0x41)) &&
     ((char)(local_88._5_1_ - local_60._3_1_) == -3)) &&
    (((((local_50._4_1_ ^ local_78._2_1_) == 0x1a && ((local_88._1_1_ ^ local_88._3_1_) == 0x2f)
       ) && (((byte)(local_78._1_1_ - local_68._7_1_) == '+' &&
             (((((byte)((char)local_80 + local_78._4_1_) == -0x2d &&
                ((byte)(local_80._3_1_ * local_58._5_1_) == -0x28)) &&
               ((byte)(local_70._3_1_ + local_88._6_1_) == -0x2e)) &&
              (((byte)(local_88._5_1_ + local_88._3_1_) == -0x55 &&
               ((byte)(local_68._3_1_ - local_60._7_1_) == -0x2e)))))))) &&
     (((byte)local_78 ^ local_68._1_1_) == 0x10)))))))))) {
puts("Freedom at last!");
}
else {
puts("Lost in the darkness, you\'ll wander for eternity...");
```
{% endcode %}

Used a combination of [this angr solution](https://binaryresearch.github.io/2020/01/22/more-angr-defeating-5-ELF-crackmes.html), ChatGPT and manual adjustments to make a solve script.

{% code overflow="wrap" %}
```python
import angr
import claripy
from datetime import datetime


def solve():
    # Load the binary
    proj = angr.Project('./cave', main_opts={"base_addr": 0},  # this is a PIE binary, so load at offset 0x0
                        auto_load_libs=False)

    # Create symbolic variables for the input
    input_size = 0x80
    flag_chars = [claripy.BVS("input_%d" % i, 8) for i in range(input_size)]
    flag.ast = claripy.Concat(claripy.BVV(b'HTB{'), *flag_chars)

    # Set up a state at the beginning of the flag
    state = proj.factory.entry_state(stdin=flag.ast)

    # Explore the program's execution paths using angr's explorer
    sim_mgr = proj.factory.simulation_manager(state)
    print("[ %s ] exploration started..." % datetime.now().time())

    sim_mgr.explore(find=0x00001aba,     # puts("Freedom at last!");
                    avoid=[0x00001ac8,  # puts("Lost in the darkness, you\'ll wander for eternity...");
                    ])

    if len(sim_mgr.found) > 0:
        print("[ %s ] solution found..." % datetime.now().time())
        found = sim_mgr.found[0]
        flag = found.solver.eval(flag.ast, cast_to=bytes)
        print("[ %s ] %s" % (datetime.now().time(), glag))
    else:
        print("[ x ] no solution found.")


if __name__ == "__main__":
    solve()
```
{% endcode %}

{% code overflow="wrap" %}
```bash
python solve.py
WARNING  | 2023-03-19 12:13:01,252 | angr.simos.simos | stdin is constrained to 132 bytes (has_end=True). If you are only providing the first 132 bytes instead of the entire stdin, please use stdin=SimFileStream(name='stdin', content=your_first_n_bytes, has_end=False).
[ 12:13:01.257932 ] exploration started...
[ 12:13:10.287439 ] solution found...
[ 12:13:10.295723 ] b"HTB{H0p3_u_d1dn't_g3t_th15_by_h4nd,1t5_4_pr3tty_l0ng_fl4g!!!}\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\x00\x00\x00\x00\x00\x00"
```
{% endcode %}

Flag: `HTB{H0p3_u_d1dn't_g3t_th15_by_h4nd,1t5_4_pr3tty_l0ng_fl4g!!!}`

My solve script was apparently overkill, my teammate 0xM4hm0ud had a shorter one.

{% code overflow="wrap" %}
```python
import angr
import claripy

proj = angr.Project("./cave")
state = proj.factory.entry_state(add_options=angr.options.unicorn)
sm = proj.factory.simulation_manager(state)

sm.explore(find=0x400000 + 0x1aba,avoid=0x400000 + 0x1ac8)

s = sm.found[0]
print(s.posix.dumps(0))
```
{% endcode %}
