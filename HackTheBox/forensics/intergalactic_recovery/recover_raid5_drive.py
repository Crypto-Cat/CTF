from pwn import *

# Read in the two working disks
disk1 = read('disk1.img')
disk3 = read('disk3.img')

# XOR to recover disk2 from the RAID 5 array
disk3 = xor(disk1, disk3)

# Save the recovered disk
write('disk2.img', disk2)
