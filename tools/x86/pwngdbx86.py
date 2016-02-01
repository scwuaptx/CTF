import gdb
import subprocess
import re
import copy
main_arena = 0
main_arena_off = 0
main_arena_off_32 = 0
fastbinsize = 10
fastbin = []
freememoryarea = []

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

def iscplus():
    name = getprocname()
    data = subprocess.check_output("readelf -s " + name,shell=True).decode('utf8')
    if "CXX" in data :
        return True
    else :
        return False


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

def getheapbase():
    infomap = procmap()
    data = re.search(".*heap\]",infomap)
    if data :
        heapbase = data.group().split("-")[0]
        return int(heapbase,16)
    else :
        return 0


def codeaddr(): # ret (start,end)
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

def putheap():
    heapbase = getheapbase()
    if heapbase :
        print("\033[34m" + "heapbase : " + "\033[37m" + hex(heapbase))
    else :
        print("heap not found")

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
        try :
            data = gdb.execute("x/x " + sym ,to_string=True)
            if "No symbol" in data:
                return 0
            else :
                data = re.search("0x.*[0-9a-f] ",data)
                data = data.group()
                symaddr = int(data[:-1] ,16)
                return symaddr-libc
        except :
            return 0

def putoff(sym) :
    symaddr = off(sym)
    if symaddr == 0 :
        print("Not found the symbol")
    else :
        print("\033[34m" + sym  + ":" + "\033[37m" +hex(symaddr))

def got():
    procname = getprocname()
    cmd = "objdump -R "
    if iscplus :
        cmd += "--demangle "
    cmd += procname
    got = subprocess.check_output(cmd,shell=True)[:-2].decode('utf8')
    print(got)

def dyn():
    data = gdb.execute("info proc exe",to_string=True)
    procname = re.search("exe.*",data).group().split("=")[1][2:-1]
    dyn = subprocess.check_output("readelf -d " + procname,shell=True).decode('utf8')
    print(dyn)

def searchcall(sym):
    procname = getprocname()
    cmd = "objdump -d -M intel "
    if iscplus :
        cmd += "--demangle "
    cmd += procname
    try :
        call = subprocess.check_output(cmd
                + "| grep \"call.*" + sym + "@plt>\""  ,shell=True).decode('utf8')
        return call
    except :
        return "symbol not found"

def ispie():
    procname = getprocname()
    result = subprocess.check_output("readelf -h " + procname,shell=True).decode('utf8')
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
    print(output)

def attachprog(procname):
    pidlist = subprocess.check_output("pidof " + procname,shell=True).decode('utf8').split()
    gdb.execute("attach " + pidlist[0])
    if iscplus() :
        gdb.execute("set print asm-demangle on")

def rop():
    procname = getprocname()
    subprocess.call("ROPgadget --binary " + procname,shell=True)


def bcall(sym):
    call = searchcall(sym)
    if "not found" in call :
        print("symbol not found")
    else :
        if ispie():
            codebase,codeend = codeaddr()
            for callbase in call.split('\n')[:-1]: 
                addr = int(callbase.split(':')[0],16) + codebase
                cmd = "b*" + hex(addr)
                print(gdb.execute(cmd,to_string=True))
        else:
            for callbase in  call.split('\n')[:-1]:
                addr = int(callbase.split(':')[0],16)
                cmd = "b*" + hex(addr)
                print(gdb.execute(cmd,to_string=True))

def set_main_arena():
    global main_arena
    global main_arena_off
    offset = off("&main_arena")
    libc = libcbase()
    arch = getarch()
    if arch == "i386":
        main_arena_off = main_arena_off_32
    if offset :
        main_arena_off = offset
        main_arena = libc + main_arena_off
    elif main_arena_off :
        main_arena = libc + main_arena_off
    else :
        print("You need to set main arena address")

def check_overlap(addr):
    global freememoryarea
    for (start,end,chunk) in freememoryarea :
        if addr >= start and addr < end :
            return chunk
    return None

def get_fast_bin():
    global main_arena
    global fastbin
    global fastbinsize
    global freememoryarea
    fastbin = []
    freememoryarea = []
    ptrsize = 4
    word = "wx "
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
        word = "gx "
    if not main_arena:
        set_main_arena()
    if main_arena :
        for i in range(fastbinsize):
            fastbin.append([])
            chunk = {}
            is_overlap = False
            cmd = "x/" + word  + hex(main_arena + i*ptrsize + 8)
            chunk["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
            while chunk["addr"] and not is_overlap:
                cmd = "x/" + word + hex(chunk["addr"]+ptrsize*1)
                try :
                    chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
                except :
                    chunk["memerror"] = True
                    break
                is_overlap = check_overlap(chunk["addr"])
                chunk["overlap"] = is_overlap
                freememoryarea.append(copy.deepcopy((chunk["addr"],chunk["addr"]+chunk["size"],chunk)))
                fastbin[i].append(copy.deepcopy(chunk))
                cmd = "x/" + word + hex(chunk["addr"]+ptrsize*2)
                chunk = {}
                chunk["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
            if not is_overlap:
                chunk["size"] = 0
                chunk["overlap"] = False
                fastbin[i].append(copy.deepcopy(chunk))

def putfastbin():
    ptrsize = 4
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
    get_fast_bin()
    for i,bins in enumerate(fastbin) :
        cursize = (ptrsize*2)*(i+2)
        print("\033[32m(0x%02x) fastbin[%d]:\033[37m " % (cursize,i),end = "")
        for chunk in bins :
            if "memerror" in chunk :
                print("\033[33m0x%x (Memory Error)\033[37m" % chunk["addr"],end = "")
            elif (chunk["size"] & 0xf8) != cursize and chunk["addr"] != 0 :
                print("\033[36m0x%x (size error (0x%x))\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            elif chunk["overlap"] :
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x\033[31m )\033[37m" % (chunk["addr"],chunk["overlap"]["addr"]),end = "")
            else  :
                print("0x%x" % chunk["addr"],end = "")
            if chunk != bins[-1]:
                print(" --> ",end = "")
        print("")
