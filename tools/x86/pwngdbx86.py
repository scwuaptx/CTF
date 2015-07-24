import gdb
import subprocess
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

def getprocname():
    data = gdb.execute("info proc exe",to_string=True)
    procname = re.search("exe.*",data).group().split("=")[1][2:-1]
    return procname

def got():
    procname = getprocname()
    got = subprocess.check_output("objdump -R " + procname,shell=True)[:-2]
    print(got.decode('utf8'))

def dyn():
    data = gdb.execute("info proc exe",to_string=True)
    procname = re.search("exe.*",data).group().split("=")[1][2:-1]
    dyn = subprocess.check_output("readelf -d " + procname,shell=True)
    print(dyn.decode('utf8'))

def searchcall(sym):
    procname = getprocname()
    try :
        call = subprocess.check_output("objdump -d -M intel " + procname 
                + "| grep \"call.*" + sym + "@plt>\""  ,shell=True)
        return call
    except :
        return "symbol not found"

def putfindcall(sym):
    output = searchcall(sym)
    print(output.decode('utf8'))

def bcall(sym):
    call = searchcall(sym)
    if "not found" in call :
        print("symbol not found")
    else :
        for calladdr in  call.split('\n')[:-1]:
            addr = int(calladdr.split(':')[0],16)
            cmd = "b*" + hex(addr)
            print(gdb.execute(cmd,to_string=True))
