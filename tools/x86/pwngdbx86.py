import gdb
import subprocess
import re



def getarch():
    data = gdb.execute('show arch',to_string = True)
    arch =  re.search("currently.*",data)
    if arch : 
        if "x86-64" in arch.group() :
            return "x86-64"
        else :
            return  "i386"
    else :
        return "error"


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

def getprocname():
    data = gdb.execute("info proc exe",to_string=True)
    procname = re.search("exe.*",data).group().split("=")[1][2:-1]
    return procname

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


def codeaddr():
    infomap = procmap()
    procname = getprocname()
    pat = ".*" + procname
    data = re.findall(pat,infomap)
    if data :
        codebase = data[0].split("-")[0]
        codeend = data[0].split("-")[1].split()[0]
        return (int(codebase,16),int(codeend,16))
    else :
        return (0,0)

def findsyscall():
    arch = getarch()
    start,end = codeaddr()
    if arch == "x86-64" :
        gdb.execute("find 0x050f " + hex(start) + " " + hex(end) )
    elif arch == "i386":
        gdb.execute("find 0x80cd " + hex(start) + " " + hex(end) )
    else :
        print("error")

def gettls():
    arch = getarch()
    if arch == "i386" :
        tlsaddr = libcbase() - 0x1000 + 0x700
        return tlsaddr
    elif arch == "x86-64" :
        gdb.execute("call arch_prctl(0x1003,$rsp-8)")
        data = gdb.execute("x/x $rsp-8",to_string=True)
        return int(data.split(":")[1].strip(),16)
    else:
        return "error"

def getcanary():
    arch = getarch()
    tlsaddr = gettls()
    if arch == "i386" :
        offset = 0x14
        result = gdb.execute("x/x " + hex(tlsaddr + offset),to_string=True).split(":")[1].strip()
        return int(result ,16)   
    elif arch == "x86-64" :
        offset = 0x28
        result = gdb.execute("x/x " + hex(tlsaddr + offset),to_string=True).split(":")[1].strip()
        return int(result,16)
    else :
        return "error"

def puttls():
    print("\033[34m" + "tls : " + "\033[37m" + hex(gettls()))

def putlibc():
    print("\033[34m" + "libc : " + "\033[37m" + hex(libcbase()))

def putld():
    print("\033[34m" + "ld : " + "\033[37m" + hex(ldbase()))

def putcodebase():
    print("\033[34m" + "codebase : " + "\033[37m" + hex(codeaddr()[0]))

def putcanary():
    print("\033[34m" + "canary : " + "\033[37m" + hex(getcanary()))

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

def ispie():
    procname = getprocname()
    result = subprocess.check_output("readelf -h " + procname,shell=True)
    if re.search("DYN",result):
        return True
    else:
        return False

def abcd(bit):
    s = ""
    for i in range(0x7a-0x41):
        s += chr(0x41+i)*(int(bit)/8)
    print(s)

def length(bit,pat):
    off = (ord(pat) - 0x41)*(int(bit)/8)
    print(off)

def putfindcall(sym):
    output = searchcall(sym)
    print(output.decode('utf8'))

def attachprog(procname):
    pidlist = subprocess.check_output("pidof " + procname,shell=True).split()
    gdb.execute("attach " + pidlist[0])

def rop():
    procname = getprocname()
    subprocess.call("ROPgadget --binary " + procname,shell=True)


def bcall(sym):
    call = searchcall(sym)
    if "not found" in call :
        print("symbol not found")
    else :
        if ispie():
            codeaddr = codebase()
            for calladdr in call.split('\n')[:-1]: 
                addr = int(calladdr.split(':')[0],16) + codeaddr
                cmd = "b*" + hex(addr)
                print(gdb.execute(cmd,to_string=True))
        else:
            for calladdr in  call.split('\n')[:-1]:
                addr = int(calladdr.split(':')[0],16)
                cmd = "b*" + hex(addr)
                print(gdb.execute(cmd,to_string=True))
