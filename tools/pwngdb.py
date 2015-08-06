import gdb
import subprocess
import re

plt = {}

def init():
    global plt
    plt = getplt()

def showstack():
    pat = "\<.*\>"
    output = ""
    output += "\033[34m"
    data = gdb.execute('x/x $context_t ',to_string=True)[:-1]
    output += data.split(":")[0]
    output += ":"
    output += "\033[37m"
    output += data.split(":")[1]
    value = data.split(":")[1][1:]
    try :
        devalue = gdb.execute('x/wx ' + str(value),to_string=True)
        output += " --> "
        if re.search(pat,devalue):
            output += "<" + devalue.split("<")[1]
        else :
            output += devalue.split(":")[1][1:]
    except :
        output += "\n"     
    print(output,end="")

def showreg(reg):
    pat = "\<.*\>"
    output = ""
    output += gdb.execute('printf " 0x%08X ", ' + reg,to_string=True)
    try :
        devalue = gdb.execute('x/wx ' + str(output),to_string=True)
        output += " --> "
        if re.search(pat,devalue) :
            output += "<" +  devalue.split("<")[1] 
        else :
            output += devalue.split(":")[1][1:]
    except :
        output += "\n"
    print(output,end="")


def getprocname():
    data = gdb.execute("info proc exe",to_string=True)
    procname = re.search("exe.*",data).group().split("=")[1][2:-1]
    return procname

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

def vmmap():
    print(procmap(),end="")

def findstr(pat):
    infomap = procmap()
    mems = infomap.split('\n')
    for mem in mems[:-1] :
        start = int((mem.split()[0]).split("-")[0],16)
        end = int((mem.split()[0]).split("-")[1],16)  
        gdbcmd = "find " + hex(start) + "," + hex(end) + "," + "\"" + pat + "\""
        result = gdb.execute(gdbcmd ,to_string=True)
        if re.search("Pattern not found",result):
            continue 
        else :
            for addr in result.split('\n')[:-2]:
                name = mem.split()[5]
                content = (gdb.execute("x/s " + addr,to_string=True)).split()[1]
                output = "\033[34m" + addr + "\033[37m"+ " --> " + content + "\033[32m" + " (" + name + ")"+"\033[37m" + '\n'
                print(output,end="")

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

def codebase():
    infomap = procmap()
    procname = getprocname()
    pat = ".*" + procname
    data = re.search(pat,infomap)
    if data :
        codeaddr = data.group().split("-")[0]
        return int(codeaddr,16)
    else :
        return 0


def putlibc():
    print("\033[34m" + "libc : " + "\033[37m" + hex(libcbase()))


def putld():
    print("\033[34m" + "ld : " + "\033[37m" + hex(ldbase()))


def putcodebase():
    print("\033[34m" + "ld : " + "\033[37m" + hex(codebase()))

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


def abcd(bit):
    s = ""
    for i in range(0x7a-0x41):
        s += chr(0x41+i)*(int(int(bit)/8))
    print(s)

def length(bit,pat):
    off = (ord(pat) - 0x41)*(int(int(bit)/8))
    print(off)

def got():
    data = gdb.execute("info proc exe",to_string=True)
    procname = re.search("exe.*",data).group().split("=")[1][2:-1]
    got = subprocess.check_output("objdump -R " + procname,shell=True)[:-2]
    print(got.decode('utf8'))

def dyn():
    data = gdb.execute("info proc exe",to_string=True)
    procname = re.search("exe.*",data).group().split("=")[1][2:-1]
    dyn = subprocess.check_output("readelf -d " + procname,shell=True)
    print(dyn.decode('utf8'))

def getgotplt():
    gotplt = []
    procname = getprocname()
    result = subprocess.check_output("objdump -R " + procname +
            "|grep R_ARM_JUMP_SLOT",shell=True )
    result = result.decode('utf8')
    for element in result.split('\n')[:-1]:
        gotplt.append(element.split()[2])
    return gotplt

def getplt():
    plt = {}
    temp = []
    got_plt = ["plt0"]+getgotplt()
    procname = getprocname()
    result = subprocess.check_output("objdump -d -j .plt " + procname +
            "| grep -A 31337 .plt\>",shell=True).decode('utf8')
    pltentry = result.split('\n')[1:]
    temp.append(pltentry[0].split(":")[0].strip())
    pltentry = pltentry[5:]
    for i in range(int(len(pltentry)/3)):
        temp.append(pltentry[i*3].split(":")[0].strip() )
    plt = dict(zip(got_plt,temp))
    return plt

def putplt(sym):
    #plt = getplt()
    global plt
    if sym in plt :
        symplt = plt[sym]
        if sym is "plt0":
            result = gdb.execute("x/4i " + symplt,to_string=True)
        else :
            result = gdb.execute("x/3i" + symplt,to_string=True)
    else :
        result = "The symbol not found"
    print(result)

def findplt(addr):
    #plt = getplt()
    global plt
    resplt = dict(zip(plt.values(),plt.keys()))
    if addr[2:] in resplt :
        output = "the function is "
        output += "\033[33m"
        output += resplt[addr[2:]]
        output += "\033[37m"
    else :
        output = "Not found"
    print(output)

def elfsym():
    #plt = getplt()
    global plt
    for pltentry in plt :
        print("\033[33m" + pltentry + "@plt:" + "\033[37m" + hex(int(plt[pltentry],16)))

def callplt(data):
    resplt = dict(zip(plt.values(),plt.keys()))
    result =  re.search("blx.*0x.*",data)
    if result :
        addr = result.group().split("0x")[1]
        if addr in resplt: 
            return data[:-1] + " <" + resplt[addr] + ">\n" 
        return data
    else :
        return data

def showcurins() :
    ins = gdb.execute("x/i (unsigned int)$pc | (($cpsr >> 5) & 1)",to_string=True)
    print(callplt(ins),end="")

def showins():
    ins = gdb.execute("x/i",to_string=True)
    print(callplt(ins),end="")
