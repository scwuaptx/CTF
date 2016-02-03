import gdb
import subprocess
import re
import copy
main_arena = 0
main_arena_off = 0
#main_arena_off_32 = 0x1b7840
main_arena_off_32 = 0
top = {}
malloc_off = 0x844a0
malloc_off_32 = 0
free_off = 0x84850
free_off_32 = 0
last_remainder = {}
fastbinsize = 10
fastbin = []
freememoryarea = {}
allocmemoryarea = {}
unsortbin = []
smallbin = {}  #{size:bin}
tracemode = False

class Malloc_bp_ret(gdb.FinishBreakpoint):
    global allocmemoryarea
    def __init__(self):
        gdb.FinishBreakpoint.__init__(self,gdb.newest_frame(),internal=True)
        self.silent = True
    
    def stop(self):
        chunk = {}
        arch = getarch()
        if arch == "x86-64" :
            ptrsize = 8
            word = "x/gx "
        else :
            ptrsize = 4
            word = "x/wx "
        chunk["addr"] = int(self.return_value) - ptrsize*2
        cmd = word + hex(chunk["addr"] + ptrsize)
        chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
        allocmemoryarea[hex(chunk["addr"])] = copy.deepcopy((chunk["addr"],chunk["addr"]+chunk["size"],chunk))


class Malloc_Bp_handler(gdb.Breakpoint):
    def stop(self):
        Malloc_bp_ret()
        return False

class Free_Bp_handler(gdb.Breakpoint):
    def stop(self):
        global allocmemoryarea
        arch = getarch()
        ptrsize = 4
        if arch == "x86-64":
            ptrsize = 8
            reg = "$rdi"
            result = int(gdb.execute("info register " + reg,to_string=True).split()[1].strip(),16)
        else :
            ptrsize = 4
            result = int(gdb.execute("x/wx $esp+4" + reg,to_string=True).split()[1].strip(),16)
        if hex(result-ptrsize*2) in allocmemoryarea :
            del allocmemoryarea[hex(result-ptrsize*2)]
        return False


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

def check_overlap(addr,size):
    for key,(start,end,chunk) in freememoryarea.items() :
    #    print("addr 0x%x,start 0x%x,end 0x%x,size 0x%x" %(addr,start,end,size) )
        if (addr >= start and addr < end) or ((addr+size) > start and (addr+size) < end ) :
            return chunk,"freed"
    for key,(start,end,chunk) in allocmemoryarea.items() :
    #    print("addr 0x%x,start 0x%x,end 0x%x,size 0x%x" %(addr,start,end,size) )
        if (addr >= start and addr < end) or ((addr+size) > start and (addr+size) < end ) :
            return chunk,"inused"
    
    
    return None

def get_top_lastremainder():
    global main_arena
    global fastbinsize
    global top
    global last_remainder
    chunk = {}
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
        word = "gx "
    else :
        ptrsize = 4
        word = "wx "
    #get top
    cmd = "x/" + word + hex(main_arena + fastbinsize*ptrsize + 8 )
    chunk["addr"] =  int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
    chunk["size"] = 0
    if chunk["addr"] :
        cmd = "x/" + word + hex(chunk["addr"]+ptrsize*1)
        try :
            chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
            if chunk["size"] > 0x21000 :
                chunk["memerror"] = "top is broken ?"
        except :
            chunk["memerror"] = "invaild memory"
    top = copy.deepcopy(chunk)
    #get last_remainder
    chunk = {}
    cmd = "x/" + word + hex(main_arena + (fastbinsize+1)*ptrsize + 8 )
    chunk["addr"] =  int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
    chunk["size"] = 0
    if chunk["addr"] :
        cmd = "x/" + word + hex(chunk["addr"]+ptrsize*1)
        try :
            chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
        except :
            chunk["memerror"] = "invaild memory"
    last_remainder = copy.deepcopy(chunk)

def get_fast_bin():
    global main_arena
    global fastbin
    global fastbinsize
    global freememoryarea
    fastbin = []
    #freememoryarea = []
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
        word = "gx "
    else :
        ptrsize = 4
        word = "wx "
    for i in range(fastbinsize-3):
        fastbin.append([])
        chunk = {}
        is_overlap = False
        cmd = "x/" + word  + hex(main_arena + i*ptrsize + 8)
        chunk["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
        while chunk["addr"] and not is_overlap:
            cmd = "x/" + word + hex(chunk["addr"]+ptrsize*1)
            try :
                chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
            except :
                chunk["memerror"] = "invaild memory"
                break
            is_overlap = check_overlap(chunk["addr"], (ptrsize*2)*(i+2))
            chunk["overlap"] = is_overlap
            freememoryarea[hex(chunk["addr"])] = copy.deepcopy((chunk["addr"],chunk["addr"] + (ptrsize*2)*(i+2) ,chunk))
            fastbin[i].append(copy.deepcopy(chunk))
            cmd = "x/" + word + hex(chunk["addr"]+ptrsize*2)
            chunk = {}
            chunk["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
        if not is_overlap:
            chunk["size"] = 0
            chunk["overlap"] = False
            fastbin[i].append(copy.deepcopy(chunk))


def trace_normal_bin(chunkhead):
    global main_arena
    global freememoryarea  
    libc = libcbase()
    bins = []
    ptrsize = 4
    word = "wx "
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
        word = "gx "
    if chunkhead["addr"] == 0 : # main_arena not initial
        return None
    chunk = {}
    cmd = "x/" + word  + hex(chunkhead["addr"] + ptrsize*2) #fd
    chunk["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) #get fd chunk
    if (chunk["addr"] == chunkhead["addr"]) and (chunkhead["addr"] > libc):  #no chunk in the bin
        return bins
    else :
        try :
            cmd = "x/" + word + hex(chunkhead["addr"]+ptrsize*3)
            bk = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
            cmd = "x/" + word + hex(bk+ptrsize*2)
            bk_fd = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
            if bk_fd != chunkhead["addr"]:
                chunkhead["memerror"] = "\033[31mdoubly linked list corruption {0} != {1} and \033[36m{2}\033[31m is broken".format(hex(chunkhead["addr"]),hex(bk_fd),hex(chunkhead["addr"]))
                bins.append(copy.deepcopy(chunkhead))
                return bins
            fd = chunkhead["addr"]
            chunkhead = {}
            chunkhead["addr"] = bk #bins addr
            chunk["addr"] = fd #first chunk
        except :
            chunkhead["memerror"] = "invaild memory" 
            bins.append(copy.deepcopy(chunkhead))
            return bins
        while chunk["addr"] != chunkhead["addr"] and chunk["addr"] < libc:
            try :
                cmd = "x/" + word + hex(chunk["addr"])
                chunk["prev_size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
                cmd = "x/" + word + hex(chunk["addr"]+ptrsize*1)
                chunk["size"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16) & 0xfffffffffffffff8
            except :
                chunk["memerror"] = "invaild memory"
                break
            try :
                cmd = "x/" + word + hex(chunk["addr"]+ptrsize*2)
                fd = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
                cmd = "x/" + word + hex(fd + ptrsize*3)
                fd_bk = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
                if chunk["addr"] != fd_bk :
                    chunk["memerror"] = "\033[31mdoubly linked list corruption {0} != {1} and \033[36m{2}\033[31m or \033[36m{3}\033[31m is broken".format(hex(chunk["addr"]),hex(fd_bk),hex(fd),hex(chunk["addr"]))
                    bins.append(copy.deepcopy(chunk))
                    break
            except :
                chunk["memerror"] = "invaild memory"
                bins.append(copy.deepcopy(chunk))
                break
            is_overlap = check_overlap(chunk["addr"],chunk["size"])
            chunk["overlap"] = is_overlap
            freememoryarea[hex(chunk["addr"])] = copy.deepcopy((chunk["addr"],chunk["addr"] + chunk["size"] ,chunk))
            bins.append(copy.deepcopy(chunk))
            cmd = "x/" + word + hex(chunk["addr"]+ptrsize*2) #find next
            chunk = {}
            chunk["addr"] = fd
    return bins


def get_unsortbin():
    global main_arena
    global unsortbin
    unsortbin = []
    ptrsize = 4
    word = "wx "
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
        word = "gx "
    chunkhead = {}
    cmd = "x/" + word + hex(main_arena + (fastbinsize+2)*ptrsize+8)
    chunkhead["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
    unsortbin = trace_normal_bin(chunkhead)


def get_smailbin():
    global main_arena
    global smallbin
    max_smallbin_size = 512
    smallbin = {}
    ptrsize = 4
    word = "wx "
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
        word = "gx "
        max_smallbin_size *= 2
    for size in range(ptrsize*4,max_smallbin_size,ptrsize*2):
        chunkhead = {}
        idx = int((size/(ptrsize*2)))-1
        cmd = "x/" + word + hex(main_arena + (fastbinsize+2)*ptrsize+8 + idx*ptrsize*2)  # calc the smallbin index
        chunkhead["addr"] = int(gdb.execute(cmd,to_string=True).split(":")[1].strip(),16)
        bins = trace_normal_bin(chunkhead)
        if bins and len(bins) > 0 :
            smallbin[hex(size)] = copy.deepcopy(bins)


def get_heap_info():
    global main_arena
    global freememoryarea
    freememoryarea = {}
    if not main_arena:
        set_main_arena()
    if main_arena :
        get_unsortbin()
        get_smailbin()
        get_fast_bin()
        get_top_lastremainder()


def get_reg(reg):
    cmd = "info register " + reg
    result = int(gdb.execute(cmd,to_string=True).split()[1].strip(),16)
    return result


def trace_malloc():
    libc = libcbase()
    arch = getarch()
    if arch == "x86-64":
        malloc_addr = libc + malloc_off
        free_addr = libc + free_off
    else :
        malloc_addr = libc + malloc_off_32
        free_addr = libc + free_off_32

    Malloc_Bp_handler("*" + hex(malloc_addr))
    Free_Bp_handler("*" + hex(free_addr))
 

def set_trace_mode(option="on"):
    global tracemode
    if option == "on":
        tracemode = True
    else :
        tracemode = False

def putfastbin():
    ptrsize = 4
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
    get_heap_info()
    for i,bins in enumerate(fastbin) :
        cursize = (ptrsize*2)*(i+2)
        print("\033[32m(0x%02x)     fastbin[%d]:\033[37m " % (cursize,i),end = "")
        for chunk in bins :
            if "memerror" in chunk :
                print("\033[31m0x%x (%s)\033[37m" % (chunk["addr"],chunk["memerror"]),end = "")
            elif chunk["size"] != cursize and chunk["addr"] != 0 :
                print("\033[36m0x%x (size error (0x%x))\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            elif chunk["overlap"] :
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x(%s)\033[31m )\033[37m" % (chunk["addr"],chunk["overlap"][0]["addr"],chunk["overlap"][1]),end = "")
            elif chunk == bins[0]  :
                print("\033[34m0x%x\033[37m" % chunk["addr"],end = "")
            else  :
                print("0x%x" % chunk["addr"],end = "")
            if chunk != bins[-1]:
                print(" --> ",end = "")
        print("")

def putheapinfo():
    ptrsize = 4
    arch = getarch()
    if arch == "x86-64":
        ptrsize = 8
    putfastbin()
    if "memerror" in top :
        print("\033[35m %20s:\033[31m 0x%x \033[33m(size : 0x%x)\033[31m (%s)\033[37m " % ("top",top["addr"],top["size"],top["memerror"]))
    else :
        print("\033[35m %20s:\033[34m 0x%x \033[33m(size : 0x%x)\033[37m " % ("top",top["addr"],top["size"]))
    print("\033[35m %20s:\033[34m 0x%x \033[33m(size : 0x%x)\033[37m " % ("last_remainder",last_remainder["addr"],last_remainder["size"]))
    if unsortbin and len(unsortbin) > 0 :
        print("\033[35m %20s:\033[37m " % "unsortbin",end="")
        for chunk in unsortbin :
            if "memerror" in chunk :
                print("\033[31m0x%x (%s)\033[37m" % (chunk["addr"],chunk["memerror"]),end = "")
            elif chunk["overlap"] :
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x(%s)\033[31m )\033[37m" % (chunk["addr"],chunk["overlap"][0]["addr"],chunk["overlap"][1]),end = "")
            elif chunk == unsortbin[-1]:
                print("\033[34m0x%x\033[37m \33[33m(size : 0x%x)\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            else :
                print("0x%x \33[33m(size : 0x%x)\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            if chunk != unsortbin[-1]:
                print(" <--> ",end = "")
        print("")
    else :
        print("\033[35m %20s:\033[37m 0x%x" % ("unsortbin",0)) #no chunk in unsortbin
    for size,bins in smallbin.items() :
        idx = int((int(size,16)/(ptrsize*2)))-2 
        print("\033[33m(0x%03x)  %s[%2d]:\033[37m " % (int(size,16),"smallbin",idx),end="")
        for chunk in bins :
            if "memerror" in chunk :
                print("\033[31m0x%x (%s)\033[37m" % (chunk["addr"],chunk["memerror"]),end = "")
            elif chunk["size"] != int(size,16) :
                print("\033[36m0x%x (size error (0x%x))\033[37m" % (chunk["addr"],chunk["size"]),end = "")
            elif chunk["overlap"] :
                print("\033[31m0x%x (overlap chunk with \033[36m0x%x(%s)\033[31m )\033[37m" % (chunk["addr"],chunk["overlap"][0]["addr"],chunk["overlap"][1]),end = "")
            elif chunk == bins[-1]:
                print("\033[34m0x%x\033[37m" % chunk["addr"],end = "")
            else :
                print("0x%x " % chunk["addr"],end = "")
            if chunk != bins[-1]:
                print(" <--> ",end = "")
        print("")

def putinused():
    print("\033[33m %s:\033[37m " % "inused ",end="")
    for addr,(start,end,chunk) in allocmemoryarea.items() :
        print("0x%x," % (chunk["addr"]),end="")
    print("")
