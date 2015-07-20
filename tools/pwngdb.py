import gdb
import re

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

def vmmap():
    data = gdb.execute('info proc exe',to_string = True)
    pid = re.search('process.*',data)
    if pid :
        pid = pid.group()
        pid = pid.split()[1]
        maps = open("/proc/" + pid + "/maps","r")
        infomap = maps.read()
        print(infomap,end="")
        maps.close()
    else :
        print('error')
     
def findstr(pat):
    data = gdb.execute('info proc exe',to_string = True)
    pid = re.search('process.*',data)
    if pid :
        pid = pid.group()
        pid = pid.split()[1]
        maps = open("/proc/" + pid + "/maps","r")
        infomap = maps.read()
        maps.close()
    else :
        print('error')
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
