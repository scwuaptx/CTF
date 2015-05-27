import struct
import socket
import telnetlib

#pack
def pack32(data,fmt="<I"):
    return struct.pack(fmt,data)

def unpack32(data,fmt="<I"):
    return struct.unpack(fmt,data)[0]

def pack(data,fmt="<Q"):
    return struct.pack(fmt,data)

def unpack(data,fmt="<Q"):
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

#fmt
def fmtchar(prev_word,word,index,byte = 1):
    if word - prev_word > 0 :
        result = word - prev_word 
    else :
        result = 256 - prev_word + word
    if byte == 2 :
        fmt = "%" + str(result) + "c" + "%" + str(index) + "$hn"
    elif byte == 4 :
        fmt = "%" + str(result) + "c" + "%" + str(index) + "$n"
    else :
        fmt = "%" + str(result) + "c" + "%" + str(index) + "$hhn"
    return fmt
