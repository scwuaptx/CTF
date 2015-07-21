import gdb
import re

def procmap():
    data = gdb.execute('info proc exe',to_string = True)
    pid = re.search('process.*',data)
    if pid :
        pid = pid.group()
        pid = pid.split()[1]
        maps = open("/proc/" + pid + "/maps","r")
        infomap = maps.read()
        maps.close()
        return infomap
    else :
        return "error"

def libcbase():
    infomap = procmap()
    data = re.search(".*libc.*\.so",infomap)
    if data :
        libcaddr = data.group().split("-")[0]
        return int(libcaddr,16)
    else :
        return 0

def ldbase():
    infomap = procmap()
    data = re.search(".*ld.*\.so",infomap)
    if data :
        ldaddr = data.group().split("-")[0]
        return int(ldaddr,16)
    else :
        return 0

def putlibc():
    print("\033[34m" + "libc : " + "\033[37m" + hex(libcbase()))

def putld():
    print("\033[34m" + "ld : " + "\033[37m" + hex(ldbase()))

def off(sym):
    libc = libcbase()
    try :
        symaddr = int(sym,16)
        return symaddr-libc
    except :
        data = gdb.execute("x/x " + sym ,to_string=True)
        if "No symbol" in data:
            return 0
        else :
            data = re.search("0x.*[0-9a-f] ",data)
            data = data.group()
            symaddr = int(data[:-1] ,16)
            return symaddr-libc

def putoff(sym) :
    symaddr = off(sym)
    if symaddr == 0 :
        print("Not found the symbol")
    else :
        print("\033[34m" + sym  + ":" + "\033[37m" +hex(symaddr))
