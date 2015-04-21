import struct
import socket
import telnetlib

#pack
def pack(data,fmt="<I"):
    return struct.pack(fmt,data)

def unpack(data,fmt="<I"):
    return struct.unpack(fmt,data)[0]

def pack64(data,fmt="<Q"):
    return struct.pack(fmt,data)

def unpack64(data,fmt="<Q"):
    return struct.unpack(fmt,data)[0]

#Connection
def make_conn(host,port):
    sock = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
    sock.connect((host,port))
    return sock

def recvuntil(sock,delim = '\n') :
    data = ""
    while not data.endswith(delim):
        data += sock.recv(1)
    return data

def sendline(sock,data):
    sock.send(data + '\n')
    return 1

def inter(sock):
    t = telnetlib.Telnet()
    t.sock = sock
    t.interact()
